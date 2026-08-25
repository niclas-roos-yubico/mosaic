package platformauth_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/platformauth"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/server"
)

func testValidator(t *testing.T) (*platformauth.JWTValidator, string) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	t.Cleanup(srv.Close)
	v, err := platformauth.NewJWTValidator(platformauth.JWTValidatorConfig{
		JWKSURL: srv.URL, Issuer: "https://platform.example.com/platform",
		Audience: "platform-data-plane", Algorithms: []string{"RS256"},
	})
	require.NoError(t, err)
	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"tenant_a"}, time.Hour, "test-kid-1")
	return v, token
}

func TestMiddlewareStoresClaimsForResolver(t *testing.T) {
	v, token := testValidator(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var schemas []string
	var expiresAt time.Time
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolution, err := platformauth.SchemaResolver().ResolveSchemas(r)
		require.NoError(t, err)
		schemas, expiresAt = resolution.AllowedSchemas, resolution.ExpiresAt
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(platformauth.SessionHeader, token)
	res := httptest.NewRecorder()
	platformauth.Middleware(v, logger)(next).ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.Equal(t, []string{"tenant_a"}, schemas)
	require.False(t, expiresAt.IsZero())
}

func TestMiddlewareRejectsMissingToken(t *testing.T) {
	v, _ := testValidator(t)
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	res := httptest.NewRecorder()
	platformauth.Middleware(v, slog.Default())(next).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.False(t, called)
}

func TestMiddlewarePassesCORSPreflightWithoutSession(t *testing.T) {
	v, _ := testValidator(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	res := httptest.NewRecorder()
	platformauth.Middleware(v, slog.Default())(next).ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.True(t, called)
}

func TestAuthorizerDeniesExecAndAllowsJSON(t *testing.T) {
	connector, err := duckdb.NewConnector(":memory:", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connector.Close()) })
	db, err := query.New(context.Background(), connector)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	h, err := server.New(db, server.WithAuthorizer(platformauth.Authorizer()))
	require.NoError(t, err)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		return res
	}
	require.Equal(t, http.StatusForbidden, post(`{"type":"exec","sql":"SELECT 1"}`).Code)
	require.Equal(t, http.StatusOK, post(`{"type":"json","sql":"SELECT 1 AS value"}`).Code)
}

// TestMiddlewareRejectionNeverLeaksToken proves the security requirement in
// Step 5 ("no log or response contains the token"): a rejected session must
// not echo the submitted token, or any validation error detail that could
// contain it, in either the HTTP response body or the logger output.
func TestMiddlewareRejectionNeverLeaksToken(t *testing.T) {
	v, _ := testValidator(t)

	// A malformed token containing a unique, easily-greppable marker. If the
	// middleware ever echoed the raw token or the underlying jwx validation
	// error (which quotes the offending compact serialization) into the
	// response or the log, this marker would show up in one of them.
	const secretMarker = "super-secret-token-marker-should-never-leak"
	forgedToken := "not-a-real-jwt." + secretMarker + ".payload"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not be called for a rejected session")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(platformauth.SessionHeader, forgedToken)
	res := httptest.NewRecorder()
	platformauth.Middleware(v, logger)(next).ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.NotContains(t, res.Body.String(), secretMarker)
	require.NotContains(t, res.Body.String(), forgedToken)
	require.NotContains(t, logBuf.String(), secretMarker)
	require.NotContains(t, logBuf.String(), forgedToken)
}
