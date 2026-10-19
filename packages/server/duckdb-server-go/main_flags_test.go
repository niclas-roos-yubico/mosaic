package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// Subprocess flag/startup-validation tests. The module does not compile without
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
	const extAccess = "--enable-external-access=true"
	const noCache = "--disable-result-cache=true"
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
		{name: "schema match headers", args: []string{jwks, "--schema-match-headers=X-Tenant-Id"}, want: "--schema-match-headers is not permitted"},
		// LOAD by absolute path is refused after the external-access latch, and the initializer fires on
		// every connection, so permitting this in default mode would fail on pool growth, not at startup.
		{name: "extension file without external access", args: []string{jwks, "--load-extension-file=/opt/ext/quack.duckdb_extension"}, want: "--load-extension-file requires --enable-external-access=true"},
		{name: "extension file relative path", args: []string{jwks, "--enable-external-access=true", "--disable-result-cache=true", "--load-extension-file=ext/quack.duckdb_extension"}, want: "must be an absolute path"},
		{name: "extension file wrong suffix", args: []string{jwks, "--enable-external-access=true", "--disable-result-cache=true", "--load-extension-file=/opt/ext/quack.so"}, want: "must name a .duckdb_extension artifact"},
		{name: "extension file missing", args: []string{jwks, "--enable-external-access=true", "--disable-result-cache=true", "--load-extension-file=/opt/ext/absent.duckdb_extension"}, want: "is not readable"},
		// Two-tier validation only runs inside the guarded transaction, which only exists in
		// external-access mode. Accepting the root outside it configures a check that never runs.
		{name: "mirror root without external access", args: []string{jwks, "--mirror-file-root=gs://bucket/mirrors"}, want: "--mirror-file-root requires --enable-external-access=true"},
		// A root that bounds nothing must not boot. Each of these looks configured and admits everything;
		// the glob one reintroduces the sibling-prefix leak through the root rather than the comparison.
		// The message comes from query.New rather than validate, which is why these assert on its wording.
		{name: "mirror root is a glob", args: []string{jwks, extAccess, noCache, "--mirror-file-root=/srv/mirror*"}, want: "must not contain glob metacharacters"},
		{name: "mirror root is the filesystem root", args: []string{jwks, extAccess, noCache, "--mirror-file-root=/"}, want: "must not be the filesystem root"},
		{name: "mirror root is a bare bucket", args: []string{jwks, extAccess, noCache, "--mirror-file-root=gs://bucket"}, want: "must name a prefix below the bucket"},
		{name: "mirror root is a bare scheme", args: []string{jwks, extAccess, noCache, "--mirror-file-root=gs://"}, want: "must name a prefix below the bucket"},
		{name: "mirror root is relative", args: []string{jwks, extAccess, noCache, "--mirror-file-root=srv/mirror"}, want: "must be absolute"},
		{name: "mirror root traverses", args: []string{jwks, extAccess, noCache, "--mirror-file-root=/srv/../mirror"}, want: "must not contain a parent-directory segment"},
		{name: "mirror root has whitespace", args: []string{jwks, extAccess, noCache, "--mirror-file-root=/srv/mirror "}, want: "must not have leading or trailing whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, code := runTestBinary(t, binary, tt.args...)
			require.Equal(t, 1, code, output)
			require.Contains(t, output, tt.want)
		})
	}
}

// TestBinaryBootsInDefaultMode is the gap platform#azfv fell through: every other subprocess case
// asserts a *rejection*, so the binary spent the whole thinning unable to reach its own listener in
// default mode -- the external-access latch fired before upstream's db.GetExtensions, which reads the
// extension directory -- with the entire suite green. Nothing here is about flags; it asserts only
// that default mode starts, serves, and denies. Reproduces with an empty HOME too, so it does not
// depend on the runner having extensions installed.
func TestBinaryBootsInDefaultMode(t *testing.T) {
	binary := buildTestBinary(t)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwks.Close()

	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()
	// Read the log back off disk rather than sharing a buffer with the subprocess: -race flags a
	// concurrent read of an io.Writer the exec goroutine is still writing to.
	serverLog := func() string {
		payload, _ := os.ReadFile(logPath)
		return string(payload)
	}

	port := freePort(t)
	cmd := exec.Command(binary, "--platform-session-jwks-url="+jwks.URL, "--port="+port)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	var resp *http.Response
	for range 100 {
		resp, err = http.Get("http://localhost:" + port + "/")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err, "default mode never reached its listener; server log:\n%s", serverLog())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"default mode must reject an unauthenticated request, not merely start; server log:\n%s", serverLog())
}

func TestBinaryStrictDatasetPolicyRejectsLegacySchemaSession(t *testing.T) {
	binary := buildTestBinary(t)
	private, jwksHandler := processTestKey(t)
	jwks := httptest.NewServer(jwksHandler)
	t.Cleanup(jwks.Close)

	dbPath := filepath.Join(t.TempDir(), "dataset.duckdb")
	connector, err := duckdb.NewConnector(dbPath, nil)
	require.NoError(t, err)
	db := sql.OpenDB(connector)
	_, err = db.Exec(`CREATE SCHEMA sales; CREATE TABLE sales.secret_orders(id INTEGER, label VARCHAR); INSERT INTO sales.secret_orders VALUES (1, 'denied')`)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	require.NoError(t, connector.Close())

	port := freePort(t)
	cmd := exec.Command(binary,
		"--database="+dbPath,
		"--address=127.0.0.1",
		"--port="+port,
		"--platform-session-jwks-url="+jwks.URL,
		"--platform-jwt-iss=https://platform.example.com/platform",
		"--platform-jwt-alg=RS256",
		"--require-dataset-policy=true",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	client := &http.Client{Timeout: time.Second}
	var resp *http.Response
	for range 100 {
		resp, err = client.Post("http://127.0.0.1:"+port+"/", "application/json", strings.NewReader(`{"type":"json","sql":"SELECT * FROM sales.secret_orders"}`))
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, err)
	// The first request above is intentionally unauthenticated and only waits for readiness.

	token := processLegacyToken(t, private)
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+port+"/", strings.NewReader(`{"type":"json","sql":"SELECT * FROM sales.secret_orders"}`))
	require.NoError(t, err)
	req.Header.Set("X-Platform-Session", token)
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func processTestKey(t *testing.T) (*rsa.PrivateKey, http.Handler) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	public, err := jwk.PublicRawKeyOf(private)
	require.NoError(t, err)
	key, err := jwk.Import(public)
	require.NoError(t, err)
	_ = key.Set(jwk.KeyIDKey, "process-test-kid")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	return private, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
}

func processLegacyToken(t *testing.T, private *rsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	token := jwt.New()
	for key, value := range map[string]any{
		jwt.IssuerKey:     "https://platform.example.com/platform",
		jwt.AudienceKey:   []string{"platform-data-plane"},
		jwt.SubjectKey:    "process-test-user",
		jwt.IssuedAtKey:   now,
		jwt.NotBeforeKey:  now,
		jwt.ExpirationKey: now.Add(time.Minute),
		jwt.JwtIDKey:      "process-test-jti",
		"allowed_schemas": []string{"sales"},
	} {
		require.NoError(t, token.Set(key, value))
	}
	key, err := jwk.Import(private)
	require.NoError(t, err)
	_ = key.Set(jwk.KeyIDKey, "process-test-kid")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)
	return string(signed)
}

// freePort asks the kernel for an unused port and immediately gives it back. Racy in principle;
// the alternative is parsing the listener address out of the subprocess's log, which is more code
// for a narrower guarantee.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func TestUsageAdvertisesHardenedFlags(t *testing.T) {
	binary := buildTestBinary(t)
	output, code := runTestBinary(t, binary, "-h")
	require.Zero(t, code, output)
	for _, flag := range []string{
		"platform-session-jwks-url", "platform-jwt-iss", "platform-jwt-alg",
		"enable-external-access", "disable-result-cache", "query-transaction-timeout",
		"max-query-result-bytes", "quack-bootstrap-fd", "function-allowlist",
		"load-extension-file", "require-dataset-policy",
	} {
		require.Contains(t, output, flag)
	}
}

func TestREADMEDocumentsPlatformSecurityContract(t *testing.T) {
	payload, err := os.ReadFile("README.md")
	require.NoError(t, err)
	readme := string(payload)
	for _, required := range []string{
		"--platform-session-jwks-url", "--enable-external-access",
		"--disable-result-cache", "--query-transaction-timeout",
		"--max-query-result-bytes", "--quack-bootstrap-fd",
		"preagg: { enabled: false }", "session expired",
		"There is no `--catalog-invariant-refresh`",
	} {
		require.Contains(t, readme, required)
	}
}
