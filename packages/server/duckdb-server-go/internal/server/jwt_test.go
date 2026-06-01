package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/Yubico/mosaic/packages/server/duckdb-server-go/internal/server"
)

// genTestKey generates a fresh RSA key pair and returns the private key and
// a JWKS HTTP handler serving the corresponding public JWK with kid="test-kid-1".
func genTestKey(t *testing.T) (*rsa.PrivateKey, http.Handler) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubKey, err := jwk.PublicRawKeyOf(priv)
	if err != nil {
		t.Fatalf("public raw key: %v", err)
	}
	set := jwk.NewSet()
	k, err := jwk.Import(pubKey)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	_ = k.Set(jwk.KeyIDKey, "test-kid-1")
	_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = k.Set(jwk.KeyUsageKey, jwk.ForSignature)
	_ = set.AddKey(k)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		raw, _ := json.Marshal(set)
		_, _ = w.Write(raw)
	})
	return priv, handler
}

// mintToken mints a session JWT signed by priv with the given overrides applied.
func mintToken(t *testing.T, priv *rsa.PrivateKey, iss, aud string, allowedSchemas []string, ttl time.Duration, kid string) string {
	t.Helper()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, iss)
	_ = tok.Set(jwt.AudienceKey, []string{aud})
	_ = tok.Set(jwt.SubjectKey, "user123")
	now := time.Now()
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.NotBeforeKey, now)
	_ = tok.Set(jwt.ExpirationKey, now.Add(ttl))
	_ = tok.Set(jwt.JwtIDKey, "jti-test-1")
	_ = tok.Set("allowed_schemas", allowedSchemas)

	privKey, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import private: %v", err)
	}
	_ = privKey.Set(jwk.KeyIDKey, kid)
	_ = privKey.Set(jwk.AlgorithmKey, jwa.RS256())

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

func TestValidToken(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings", "information_schema"}, time.Hour, "test-kid-1")

	claims, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if len(claims.AllowedSchemas) != 2 {
		t.Errorf("expected 2 allowed_schemas, got %d", len(claims.AllowedSchemas))
	}
}

func TestExpiredToken(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, -time.Hour, "test-kid-1") // already expired

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestWrongAudience(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	token := mintToken(t, priv, "https://platform.example.com/platform", "wrong-audience",
		[]string{"bookings"}, time.Hour, "test-kid-1")

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestWrongIssuer(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	token := mintToken(t, priv, "https://attacker.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, time.Hour, "test-kid-1")

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestBadSignature(t *testing.T) {
	_, jwksHandler := genTestKey(t) // JWKS has key A
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	// But we mint with key B
	privB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	v, vErr := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if vErr != nil {
		t.Fatalf("NewJWTValidator: %v", vErr)
	}

	token := mintToken(t, privB, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, time.Hour, "test-kid-1") // kid matches but key doesn't

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for bad signature, got nil")
	}
}

func TestMissingAllowedSchemasClaim(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// mint without allowed_schemas
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, "https://platform.example.com/platform")
	_ = tok.Set(jwt.AudienceKey, []string{"platform-data-plane"})
	_ = tok.Set(jwt.SubjectKey, "user123")
	now := time.Now()
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.NotBeforeKey, now)
	_ = tok.Set(jwt.ExpirationKey, now.Add(time.Hour))
	_ = tok.Set(jwt.JwtIDKey, "jti-no-schemas")

	privKey, _ := jwk.Import(priv)
	_ = privKey.Set(jwk.KeyIDKey, "test-kid-1")
	_ = privKey.Set(jwk.AlgorithmKey, jwa.RS256())
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))

	_, err = v.Validate(context.Background(), string(signed))
	if err == nil {
		t.Fatal("expected error for missing allowed_schemas, got nil")
	}
}

func TestJWKSUnavailableFailsClosed(t *testing.T) {
	priv, _ := genTestKey(t)
	// No server — JWKS URL points to nothing
	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    "http://127.0.0.1:1", // nothing listening
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, time.Hour, "test-kid-1")

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error when JWKS unavailable (fail-closed), got nil")
	}
}

func TestUnknownKidTriggersRefreshThenFails(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	refreshCount := 0
	countingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCount++
		jwksHandler.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(countingHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// Token with an unknown kid
	token := mintToken(t, priv, "https://platform.example.com/platform", "platform-data-plane",
		[]string{"bookings"}, time.Hour, "unknown-kid-999")

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
	if refreshCount < 2 {
		// Initial fetch + one refresh on kid miss
		t.Errorf("expected at least 2 JWKS fetches (initial + kid-miss refresh), got %d", refreshCount)
	}
}

func TestNotYetValid(t *testing.T) {
	priv, jwksHandler := genTestKey(t)
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	v, err := server.NewJWTValidator(server.JWTValidatorConfig{
		JWKSURL:    srv.URL,
		Issuer:     "https://platform.example.com/platform",
		Audience:   "platform-data-plane",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// nbf one hour in the future
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, "https://platform.example.com/platform")
	_ = tok.Set(jwt.AudienceKey, []string{"platform-data-plane"})
	_ = tok.Set(jwt.SubjectKey, "user123")
	now := time.Now()
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.NotBeforeKey, now.Add(time.Hour))   // not yet valid
	_ = tok.Set(jwt.ExpirationKey, now.Add(2*time.Hour))
	_ = tok.Set(jwt.JwtIDKey, "jti-futurenbf")
	_ = tok.Set("allowed_schemas", []string{"bookings"})

	privKey, _ := jwk.Import(priv)
	_ = privKey.Set(jwk.KeyIDKey, "test-kid-1")
	_ = privKey.Set(jwk.AlgorithmKey, jwa.RS256())
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))

	_, err = v.Validate(context.Background(), string(signed))
	if err == nil {
		t.Fatal("expected error for not-yet-valid token, got nil")
	}
}
