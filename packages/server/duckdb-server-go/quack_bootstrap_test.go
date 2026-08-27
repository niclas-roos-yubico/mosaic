package main

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validBootstrapJSON() string {
	return `{"version":1,"port":9494,"token":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`
}

func bootstrapToken(size int) string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, size))
}

func TestQuackBootstrapDecode(t *testing.T) {
	valid := validBootstrapJSON()
	tests := []struct {
		name      string
		input     string
		wantError string
	}{
		{name: "unsupported version", input: strings.Replace(valid, `"version":1`, `"version":2`, 1), wantError: "unsupported version"},
		{name: "zero port", input: strings.Replace(valid, `"port":9494`, `"port":0`, 1), wantError: "port must be between 1 and 65535"},
		{name: "large port", input: strings.Replace(valid, `"port":9494`, `"port":65536`, 1), wantError: "port must be between 1 and 65535"},
		{name: "short token", input: strings.Replace(valid, bootstrapToken(32), bootstrapToken(31), 1), wantError: "token must decode to exactly 32 bytes"},
		{name: "long token", input: strings.Replace(valid, bootstrapToken(32), bootstrapToken(33), 1), wantError: "token must decode to exactly 32 bytes"},
		{name: "padded token", input: strings.Replace(valid, bootstrapToken(32), bootstrapToken(32)+"=", 1), wantError: "invalid base64url token"},
		{name: "unknown field", input: strings.TrimSuffix(valid, "}") + `,"extra":true}`, wantError: "unknown field"},
		{name: "trailing object", input: valid + `{}`, wantError: "trailing data"},
		{name: "oversized", input: strings.Repeat(" ", maxQuackBootstrapBytes+1), wantError: "exceeds 4096 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readQuackBootstrap(strings.NewReader(tt.input))
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

func TestQuackBootstrapDecodeValid(t *testing.T) {
	cfg, err := readQuackBootstrap(strings.NewReader(validBootstrapJSON()))
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Version)
	require.Equal(t, 9494, cfg.Port)
	decoded, err := base64.RawURLEncoding.DecodeString(cfg.Token)
	require.NoError(t, err)
	require.Len(t, decoded, 32)
}

type quackExecer struct {
	statement string
	args      []driver.NamedValue
	err       error
}

func (f *quackExecer) ExecContext(_ context.Context, statement string, args []driver.NamedValue) (driver.Result, error) {
	f.statement = statement
	f.args = append([]driver.NamedValue(nil), args...)
	return driver.RowsAffected(0), f.err
}

func TestStartQuackUsesBoundParameters(t *testing.T) {
	const token = "known-secret-token"
	fake := &quackExecer{}
	require.NoError(t, startQuackOn(t.Context(), fake, quackBootstrapConfig{Version: 1, Port: 9494, Token: token}))
	require.Equal(t, `CALL quack_serve(?, token => ?, allow_other_hostname => false, disable_ssl => true)`, fake.statement)
	require.Equal(t, "quack:127.0.0.1:9494", fake.args[0].Value)
	require.Equal(t, token, fake.args[1].Value)
	require.NotContains(t, fake.statement, token)
}

func TestStartQuackErrorRedactsBootstrapSecrets(t *testing.T) {
	const token = "known-secret-token"
	const rawPayload = `{"version":1,"port":9494,"token":"known-secret-token"}`
	fake := &quackExecer{err: errors.New("bind failed")}
	err := startQuackOn(t.Context(), fake, quackBootstrapConfig{Version: 1, Port: 9494, Token: token})
	require.ErrorContains(t, err, "bind failed")
	require.NotContains(t, err.Error(), token)
	require.NotContains(t, err.Error(), rawPayload)
}

// inheritedFD hands readQuackBootstrapFD a descriptor shaped like the one it actually gets in
// production: inherited from the parent and owned by no *os.File in this process.
//
// Passing int(r.Fd()) instead leaves r registered with the runtime poller for that same descriptor
// number, and os.NewFile then tries to register it a second time. On Linux epoll_ctl(EPOLL_CTL_ADD)
// rejects that with EEXIST, so the poll.FD gets no runtime poller context and SetReadDeadline
// returns ErrNoDeadline ("file type does not support deadline") -- which is a property of the test's
// setup, not of the production path. macOS is the reason this was not caught locally: kqueue's
// EV_ADD updates an existing registration rather than failing, so the same code passes there.
// Verified both ways on linux/amd64 go1.25 and darwin/arm64.
//
// Dup also transfers ownership the way production expects: readQuackBootstrapFD closes the
// descriptor it is given, so the caller must not keep one open alongside it.
func inheritedFD(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return fd
}

func TestQuackBootstrapFDDeadline(t *testing.T) {
	// Shorten the production deadline for this test only, via the package-level var (not a
	// parameter of readQuackBootstrapFD), and restore it unconditionally afterward.
	const testDeadline = 200 * time.Millisecond
	original := quackBootstrapReadDeadline
	quackBootstrapReadDeadline = testDeadline
	t.Cleanup(func() { quackBootstrapReadDeadline = original })

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	started := time.Now()
	_, err = readQuackBootstrapFD(inheritedFD(t, r))
	elapsed := time.Since(started)

	require.Error(t, err)
	require.Truef(t, errors.Is(err, os.ErrDeadlineExceeded), "expected a genuine read-deadline timeout (os.ErrDeadlineExceeded), got: %v", err)
	require.Falsef(t, errors.Is(err, os.ErrNoDeadline), "SetReadDeadline must not fail eagerly with ErrNoDeadline, got: %v", err)
	require.GreaterOrEqual(t, elapsed, testDeadline, "deadline must actually fire, not return instantly")
	require.Less(t, elapsed, 6*time.Second)
}

func TestQuackBootstrapFDReadsClosedPipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(validBootstrapJSON())
	require.NoError(t, err)
	require.NoError(t, w.Close())
	cfg, err := readQuackBootstrapFD(inheritedFD(t, r))
	require.NoError(t, err)
	require.Equal(t, 9494, cfg.Port)
}
