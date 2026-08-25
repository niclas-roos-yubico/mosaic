package platformauth_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/platformauth"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/server"
)

type enforcedServer struct {
	handler   http.Handler
	private   *rsa.PrivateKey
	connector *duckdb.Connector
}

func newEnforcedServer(t *testing.T, seedSQL string, transaction query.TransactionOptions) *enforcedServer {
	t.Helper()
	private, jwksHandler := genTestKey(t)
	jwks := httptest.NewServer(jwksHandler)
	t.Cleanup(jwks.Close)
	validator, err := platformauth.NewJWTValidator(platformauth.JWTValidatorConfig{
		JWKSURL: jwks.URL, Issuer: "https://platform.example.com/platform",
		Audience: "platform-data-plane", Algorithms: []string{"RS256"}, ClockSkew: time.Millisecond,
	})
	require.NoError(t, err)
	// A seed *query.DB and the main guarded *query.DB must not share one
	// *duckdb.Connector: (*sql.DB).Close cascades to closing the driver
	// connector it wraps, so seed.Close() below would tear down the native
	// DuckDB handle the main db then tries to reuse ("could not connect to
	// database"). Mirrors the documented pattern in
	// pkg/query/transaction_test.go's guardedTransactionDB: seed through an
	// independent connector against the same file, close it fully, then open
	// a fresh connector for the guarded db.
	path := filepath.Join(t.TempDir(), "server.duckdb")
	if seedSQL != "" {
		seedConnector, err := duckdb.NewConnector(path, nil)
		require.NoError(t, err)
		seed, err := query.New(t.Context(), seedConnector)
		require.NoError(t, err)
		require.NoError(t, seed.Exec(t.Context(), seedSQL))
		seed.Close()
		require.NoError(t, seedConnector.Close())
	}
	connector, err := duckdb.NewConnector(path, nil)
	require.NoError(t, err)
	db, err := query.New(t.Context(), connector,
		query.WithMaxConnections(1),
		query.WithResultCacheDisabled(),
		query.WithTransactionalCatalogGuard(transaction),
		query.WithFunctionAllowlist(query.FunctionAllowlistOptions{}),
		query.WithRemoteURILiteralRejection(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); require.NoError(t, connector.Close()) })
	mosaic, err := server.New(db,
		server.WithAuthorizer(platformauth.Authorizer()),
		server.WithSchemaResolver(platformauth.SchemaResolver()),
		server.WithWebSocket(server.WebSocketOptions{AllowAllOrigins: true}),
	)
	require.NoError(t, err)
	return &enforcedServer{
		handler: platformauth.Middleware(validator, slog.New(slog.NewTextHandler(io.Discard, nil)))(mosaic),
		private: private, connector: connector,
	}
}

func (s *enforcedServer) token(t *testing.T, schemas []string, ttl time.Duration) string {
	return mintToken(t, s.private, "https://platform.example.com/platform", "platform-data-plane", schemas, ttl, "test-kid-1")
}

func postCommand(t *testing.T, handler http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if token != "" {
		req.Header.Set(platformauth.SessionHeader, token)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func TestRegressionPublicPolicyStack(t *testing.T) {
	s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.secret(value VARCHAR); INSERT INTO tenant_a.secret VALUES ('tenant-a-only')`,
		query.TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	tokenA := s.token(t, []string{"tenant_a"}, time.Hour)
	tokenB := s.token(t, []string{"tenant_b"}, time.Hour)
	const selectBody = `{"type":"json","sql":"SELECT * FROM tenant_a.secret","persist":true}`

	require.Equal(t, http.StatusUnauthorized, postCommand(t, s.handler, "", selectBody).Code)
	allowed := postCommand(t, s.handler, tokenA, selectBody)
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
	require.Contains(t, allowed.Body.String(), "tenant-a-only")
	require.Empty(t, allowed.Header().Get("Cache-Status"))
	denied := postCommand(t, s.handler, tokenB, selectBody)
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	require.NotContains(t, denied.Body.String(), "tenant-a-only")

	execDenied := postCommand(t, s.handler, tokenA, `{"type":"exec","sql":"CREATE SCHEMA attacker"}`)
	require.Equal(t, http.StatusForbidden, execDenied.Code, execDenied.Body.String())
	fileDenied := postCommand(t, s.handler, tokenA,
		`{"type":"json","sql":"SELECT * FROM read_csv('/var/run/secrets/kubernetes.io/serviceaccount/token')"}`)
	require.Equal(t, http.StatusForbidden, fileDenied.Code, fileDenied.Body.String())
	remoteDenied := postCommand(t, s.handler, tokenA,
		`{"type":"json","sql":"SELECT * FROM read_parquet('https://example.com/data.parquet')"}`)
	require.Equal(t, http.StatusForbidden, remoteDenied.Code, remoteDenied.Body.String())
}

func TestRegressionViewIsNotAQueryableBaseTable(t *testing.T) {
	s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE VIEW tenant_a.file_view AS SELECT 'canary' AS value`,
		query.TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	res := postCommand(t, s.handler, s.token(t, []string{"tenant_a"}, time.Hour),
		`{"type":"json","sql":"SELECT * FROM tenant_a.file_view"}`)
	require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
	require.NotContains(t, res.Body.String(), "canary")
}

func TestRegressionUserMacroFailsClosed(t *testing.T) {
	s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.safe(value INTEGER); CREATE MACRO tenant_a.range(n) AS TABLE SELECT 'canary' AS value`,
		query.TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	res := postCommand(t, s.handler, s.token(t, []string{"tenant_a"}, time.Hour),
		`{"type":"json","sql":"SELECT * FROM tenant_a.safe"}`)
	require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
	require.NotContains(t, res.Body.String(), "canary")
}

func TestRegressionGuardedHTTPErrorMapping(t *testing.T) {
	t.Run("response too large", func(t *testing.T) {
		s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.values(value VARCHAR); INSERT INTO tenant_a.values VALUES ('long-value')`,
			query.TransactionOptions{Timeout: time.Second, MaxResultBytes: 4})
		res := postCommand(t, s.handler, s.token(t, []string{"tenant_a"}, time.Hour),
			`{"type":"json","sql":"SELECT * FROM tenant_a.values"}`)
		require.Equal(t, http.StatusRequestEntityTooLarge, res.Code, res.Body.String())
	})
	t.Run("query timeout", func(t *testing.T) {
		s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.safe(value INTEGER); INSERT INTO tenant_a.safe VALUES (1)`,
			query.TransactionOptions{Timeout: time.Millisecond, MaxResultBytes: 1 << 20})
		res := postCommand(t, s.handler, s.token(t, []string{"tenant_a"}, time.Hour),
			`{"type":"json","sql":"SELECT sum(i) FROM range(1000000000) t(i) CROSS JOIN tenant_a.safe"}`)
		require.Equal(t, http.StatusGatewayTimeout, res.Code, res.Body.String())
	})
}

func TestRegressionWebSocketClosesAtJWTExpiry(t *testing.T) {
	s := newEnforcedServer(t, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.safe(value INTEGER); INSERT INTO tenant_a.safe VALUES (1)`,
		query.TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	httpServer := httptest.NewServer(s.handler)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{platformauth.SessionHeader: []string{s.token(t, []string{"tenant_a"}, 2*time.Second)}},
	})
	require.NoError(t, err)
	defer conn.CloseNow()
	require.NoError(t, wsjson.Write(ctx, conn, map[string]any{
		"type": "json", "sql": "SELECT * FROM tenant_a.safe",
	}))
	var first json.RawMessage
	require.NoError(t, wsjson.Read(ctx, conn, &first))
	require.Contains(t, string(first), "1")
	_, _, err = conn.Read(ctx)
	require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err), "error: %v", err)
	require.Contains(t, err.Error(), "session expired")
}
