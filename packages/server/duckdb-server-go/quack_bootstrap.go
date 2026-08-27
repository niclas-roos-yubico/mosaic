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
	"log/slog"
	"os"
	"syscall"
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

// quackBootstrapReadDeadline bounds how long readQuackBootstrapFD waits for the parent to write
// the bootstrap payload before giving up. It is a package-level var rather than a parameter of
// readQuackBootstrapFD so a test can shorten it without adding a test-only knob to the production
// function signature; production code never assigns to it.
var quackBootstrapReadDeadline = 5 * time.Second

func readQuackBootstrapFD(fd int) (quackBootstrapConfig, error) {
	if fd < 3 {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: descriptor must be at least 3")
	}
	// Inherited descriptors arrive in blocking mode. os.NewFile only registers a file with the
	// runtime poller -- which is what makes SetReadDeadline below actually work -- when the fd is
	// already non-blocking at wrap time; otherwise SetReadDeadline fails immediately with
	// ErrNoDeadline and no read is ever attempted, so even a well-behaved parent's payload could
	// never be read. Do not remove this call: it looks redundant with SetReadDeadline, but the
	// deadline cannot arm without it.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: set nonblocking: %w", err)
	}
	file := os.NewFile(uintptr(fd), "quack-bootstrap")
	if file == nil {
		return quackBootstrapConfig{}, errors.New("quack bootstrap: invalid descriptor")
	}
	defer func() { _ = file.Close() }()
	if err := file.SetReadDeadline(time.Now().Add(quackBootstrapReadDeadline)); err != nil {
		return quackBootstrapConfig{}, fmt.Errorf("quack bootstrap: set read deadline: %w", err)
	}
	return readQuackBootstrap(file)
}

// startQuackIfConfigured gates the Quack bootstrap on fd and owns the lifetime of the resulting
// connection. It runs before the public listener, and the returned close function must be deferred
// for the whole process lifetime or the writer dies. On success the closer is always non-nil --
// including when Quack is disabled -- so run() defers it unconditionally with no branch. No path
// here logs the descriptor number, the token, the config, or the payload.
//
// The second return value reports whether quack_serve actually ran. It feeds addLogFields so the
// startup log states the outcome rather than the flag; see the note there.
func startQuackIfConfigured(ctx context.Context, connector *duckdb.Connector, fd int, logger *slog.Logger) (func(), bool, error) {
	if fd < 3 {
		return func() {}, false, nil
	}
	cfg, err := readQuackBootstrapFD(fd)
	if err != nil {
		logger.Error("main: failed to read Quack bootstrap", "error", err)
		return nil, false, err
	}
	conn, err := startQuack(ctx, connector, cfg)
	if err != nil {
		logger.Error("main: failed to start Quack", "error", err)
		return nil, false, err
	}
	return func() {
		if err := conn.Close(); err != nil {
			logger.Error("main: failed to close Quack connection", "error", err)
		}
	}, true, nil
}
