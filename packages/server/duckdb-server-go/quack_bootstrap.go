package main

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/duckdb/duckdb-go/v2"
)

const maxQuackBootstrapBytes = 4 << 10

type quackBootstrapConfig struct {
	Version int    `json:"version"`
	Port    int    `json:"port"`
	Token   string `json:"token"`
}

func readQuackBootstrap(r io.Reader) (quackBootstrapConfig, error) {
	limited := io.LimitReader(r, maxQuackBootstrapBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: read: %w", err)
	}
	if len(payload) > maxQuackBootstrapBytes {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: payload exceeds %d bytes", maxQuackBootstrapBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cfg quackBootstrapConfig
	if err := decoder.Decode(&cfg); err != nil {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: trailing data")
	}
	if cfg.Version != 1 {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: unsupported version %d", cfg.Version)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: port must be between 1 and 65535")
	}
	token, err := base64.RawURLEncoding.DecodeString(cfg.Token)
	if err != nil {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: invalid base64url token")
	}
	if len(token) != 32 {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: token must decode to exactly 32 bytes")
	}
	return cfg, nil
}

func startQuackOn(ctx context.Context, execer driver.ExecerContext, cfg quackBootstrapConfig) error {
	statement := `CALL quack_serve(?, token => ?, allow_other_hostname => false, disable_ssl => true)`
	args := []driver.NamedValue{
		{Ordinal: 1, Value: fmt.Sprintf("quack:127.0.0.1:%d", cfg.Port)},
		{Ordinal: 2, Value: cfg.Token},
	}
	if _, err := execer.ExecContext(ctx, statement, args); err != nil {
		return fmt.Errorf("quack bootstrap: quack_serve failed: %w", err)
	}
	return nil
}

func startQuack(ctx context.Context, connector *duckdb.Connector, cfg quackBootstrapConfig) (driver.Conn, error) {
	conn, err := connector.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("quack bootstrap: connect: %w", err)
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("quack bootstrap: connection cannot execute")
	}
	startCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := startQuackOn(startCtx, execer, cfg); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func readQuackBootstrapFD(fd int) (quackBootstrapConfig, error) {
	if fd < 3 {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: descriptor must be at least 3")
	}
	file := os.NewFile(uintptr(fd), "quack-bootstrap")
	if file == nil {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: invalid descriptor")
	}
	defer func() { _ = file.Close() }()
	if err := file.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: set read deadline: %w", err)
	}
	return readQuackBootstrap(file)
}
