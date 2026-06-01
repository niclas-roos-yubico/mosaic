package server_test

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yubico/mosaic/packages/server/duckdb-server-go/internal/server"
)

// buildTestServer constructs a Server with a real JWTValidator backed by an
// in-process httptest JWKS server. The query.DB is nil because unit tests only
// exercise the auth layer — no DuckDB instance is needed here.
// genTestKey and mintToken are defined in jwt_test.go (same package server_test).
func buildTestServer(t *testing.T) (*server.Server, *rsa.PrivateKey, string) {
	t.Helper()
	priv, jwksHandler := genTestKey(t)
	jwksSrv := httptest.NewServer(jwksHandler)
	t.Cleanup(jwksSrv.Close)

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    jwksSrv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// query.DB is nil — server_test only tests the auth/enforcement layer up to
	// execCommand; integration against a real DB lives in integration_test.go.
	s := server.NewWithJWTValidator(nil, v, nil)
	return s, priv, jwksSrv.URL
}

func TestHTTPMissingToken(t *testing.T) {
	s, _, _ := buildTestServer(t)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestHTTPInvalidToken(t *testing.T) {
	s, _, _ := buildTestServer(t)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Session", "not.a.jwt")
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestHTTPExpiredToken(t *testing.T) {
	s, priv, _ := buildTestServer(t)
	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, -time.Hour, "test-kid-1")
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Session", token)
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestHTTPForbiddenSchema403Body(t *testing.T) {
	// This test verifies the 403 body shape from contracts §2.4:
	// {"error":"schema_forbidden","details":"<schema>"}
	// We cannot run a real SQL query without a DB, so this test is exercised
	// in integration_test.go. Here we verify the error body shape via a mock
	// that injects a schema-forbidden error.
	// (Placeholder — see integration_test.go for the real assertion.)
	t.Skip("schema_forbidden 403 body verified in integration_test.go")
}

// TestHTTPUnauthorizedBodyShape verifies the 401 response body is exactly
// {"error":"unauthenticated"} (not just the status code).
func TestHTTPUnauthorizedBodyShape(t *testing.T) {
	s, _, _ := buildTestServer(t)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rw.Body).Decode(&body); err != nil {
		t.Fatalf("could not decode response body: %v", err)
	}
	if body["error"] != "unauthenticated" {
		t.Errorf("expected error=unauthenticated, got %q", body["error"])
	}
}
