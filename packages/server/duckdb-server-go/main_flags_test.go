package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// FORK: subprocess flag/startup-validation tests for Task 10. The module does not compile without
// -tags=duckdb_arrow (see .golangci.yaml and README.md), so buildTestBinary must pass it through to
// the subprocess `go build` or every case below fails with an unrelated build error.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "duckdb-server")
	cmd := exec.Command("go", "build", "-tags=duckdb_arrow", "-o", binary, ".")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	return binary
}

func runTestBinary(t *testing.T, binary string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), 0
	}
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "error: %v; output: %s", err, output)
	return string(output), exitErr.ExitCode()
}

func TestBinaryRejectsUnsafeModes(t *testing.T) {
	binary := buildTestBinary(t)
	const jwks = "--platform-session-jwks-url=http://127.0.0.1:1/jwks"
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing jwks", want: "--platform-session-jwks-url is required"},
		{name: "reserved descriptor", args: []string{jwks, "--quack-bootstrap-fd=2"}, want: "must be -1 or at least 3"},
		{name: "quack without external access", args: []string{jwks, "--quack-bootstrap-fd=3"}, want: "requires --enable-external-access=true"},
		{name: "external access with cache", args: []string{jwks, "--enable-external-access=true"}, want: "requires --disable-result-cache=true"},
		{name: "zero transaction timeout", args: []string{jwks, "--enable-external-access=true", "--disable-result-cache=true", "--query-transaction-timeout=0s"}, want: "must be positive"},
		{name: "negative transaction timeout", args: []string{jwks, "--query-transaction-timeout=-1s"}, want: "--query-transaction-timeout must be positive"},
		{name: "zero result limit", args: []string{jwks, "--max-query-result-bytes=0"}, want: "--max-query-result-bytes must be positive"},
		{name: "function blocklist", args: []string{jwks, "--function-blocklist=read_csv"}, want: "function blocklist is not permitted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, code := runTestBinary(t, binary, tt.args...)
			require.Equal(t, 1, code, output)
			require.Contains(t, output, tt.want)
		})
	}
}

func TestUsageAdvertisesHardenedFlags(t *testing.T) {
	binary := buildTestBinary(t)
	output, code := runTestBinary(t, binary, "-h")
	require.Zero(t, code, output)
	for _, flag := range []string{
		"platform-session-jwks-url", "platform-jwt-iss", "platform-jwt-alg",
		"enable-external-access", "disable-result-cache", "query-transaction-timeout",
		"max-query-result-bytes", "quack-bootstrap-fd", "function-allowlist",
	} {
		require.Contains(t, output, flag)
	}
	require.NotContains(t, output, "schema-match-headers")
}
