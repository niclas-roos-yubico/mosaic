package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// SessionClaims are the validated claims extracted from a Platform session JWT.
// Matches contracts §2.1.
type SessionClaims struct {
	Sub            string
	AllowedSchemas []string
	Issuer         string
	Audience       string
	JTI            string
}

// JWTValidatorConfig configures the JWT validator.
type JWTValidatorConfig struct {
	JWKSURL    string        // e.g. http://<platform-svc>/.well-known/jwks.json
	Issuer     string        // expected iss; must match WS-D minter exactly
	Audience   string        // expected aud; default "platform-data-plane"
	Algorithms []string      // allowlist; default ["RS256"]; never "none" or HS*
	ClockSkew  time.Duration // default 60s
}

// JWTValidator validates Platform session JWTs, caching JWKS with conditional GET.
// Fail-closed: any JWKS fetch failure (when no usable cache) → validation error.
type JWTValidator struct {
	cfg         JWTValidatorConfig
	algSet      []jwa.SignatureAlgorithm
	mu          sync.RWMutex
	cachedSet   jwk.Set
	lastEtag    string
	lastFetched time.Time
	cacheTTL    time.Duration
}

// NewJWTValidator creates a JWTValidator. It does NOT fetch the JWKS immediately;
// the first call to Validate fetches it.
func NewJWTValidator(cfg JWTValidatorConfig) (*JWTValidator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("jwt: JWKSURL is required")
	}
	if cfg.Audience == "" {
		cfg.Audience = "platform-data-plane"
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256"}
	}

	// Validate algorithms: reject none, HS*, and unknown algs.
	// In jwx/v3, LookupSignatureAlgorithm returns (SignatureAlgorithm, bool).
	algSet := make([]jwa.SignatureAlgorithm, 0, len(cfg.Algorithms))
	for _, a := range cfg.Algorithms {
		sa, ok := jwa.LookupSignatureAlgorithm(a)
		if !ok {
			return nil, fmt.Errorf("jwt: unknown algorithm %q", a)
		}
		// Reject none (NoSignature) and symmetric HMAC algorithms.
		switch sa {
		case jwa.NoSignature(), jwa.HS256(), jwa.HS384(), jwa.HS512():
			return nil, fmt.Errorf("jwt: algorithm %q is not allowed in the allowlist", a)
		}
		algSet = append(algSet, sa)
	}

	return &JWTValidator{
		cfg:      cfg,
		algSet:   algSet,
		cacheTTL: 5 * time.Minute,
	}, nil
}

// Validate validates the token string and returns SessionClaims on success.
// Returns a non-nil error on any failure; always fail-closed.
func (v *JWTValidator) Validate(ctx context.Context, tokenStr string) (*SessionClaims, error) {
	// Initial fetch (or serve from cache if fresh).
	keySet, err := v.getKeySet(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("jwt: could not fetch JWKS (fail-closed): %w", err)
	}

	claims, err := v.parseAndValidate(ctx, tokenStr, keySet)
	if err != nil {
		// On any parse/verify failure, force a JWKS refresh and retry once.
		// This handles the unknown-kid case: the token's kid is not in the
		// current cache, so we must re-fetch the JWKS to pick up newly issued keys.
		keySet, refreshErr := v.getKeySet(ctx, true) // force=true bypasses cache TTL
		if refreshErr != nil {
			return nil, fmt.Errorf("jwt: JWKS refresh failed (fail-closed): %w", refreshErr)
		}
		claims, err = v.parseAndValidate(ctx, tokenStr, keySet)
		if err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// getKeySet returns the cached JWKS or fetches it.
// When force=true the cache TTL is ignored and a fresh HTTP fetch is always made.
func (v *JWTValidator) getKeySet(ctx context.Context, force bool) (jwk.Set, error) {
	v.mu.RLock()
	cached := v.cachedSet
	etag := v.lastEtag
	stale := force || v.cachedSet == nil || time.Since(v.lastFetched) > v.cacheTTL
	v.mu.RUnlock()

	if !stale && cached != nil {
		return cached, nil
	}

	newSet, newEtag, err := v.fetchJWKS(ctx, etag)
	if err != nil {
		// Return cached set if available (fail-closed if no cached set at all).
		v.mu.RLock()
		c := v.cachedSet
		v.mu.RUnlock()
		if c != nil && !force {
			return c, nil // use stale cache on transient network errors
		}
		return nil, err
	}

	v.mu.Lock()
	if newSet != nil {
		v.cachedSet = newSet
		v.lastEtag = newEtag
	}
	v.lastFetched = time.Now()
	result := v.cachedSet
	v.mu.Unlock()

	if result == nil {
		return nil, fmt.Errorf("jwt: JWKS empty after fetch")
	}
	return result, nil
}

// fetchJWKS performs an HTTP GET to JWKSURL with optional If-None-Match.
// Returns (nil, oldEtag, nil) on 304 Not Modified.
func (v *JWTValidator) fetchJWKS(ctx context.Context, ifNoneMatch string) (jwk.Set, string, error) {
	req, err := newHTTPRequestWithContext(ctx, "GET", v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("jwt: build JWKS request: %w", err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("jwt: JWKS fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 304 {
		return nil, ifNoneMatch, nil // not modified; caller uses cached set
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("jwt: JWKS fetch HTTP %d", resp.StatusCode)
	}

	newSet, parseErr := jwk.ParseReader(resp.Body)
	if parseErr != nil {
		return nil, "", fmt.Errorf("jwt: JWKS parse: %w", parseErr)
	}
	newEtag := resp.Header.Get("ETag")
	return newSet, newEtag, nil
}

// parseAndValidate parses and validates the JWT against the provided key set.
// In jwx/v3.1.1:
//   - Token accessor methods (Subject, Issuer, Audience, JwtID) return (value, bool).
//   - tok.Get(key, &dst) uses a destination pointer and returns error.
//   - Use jwt.WithKeySet for key-set-based verification; do NOT combine with jwt.WithKey(alg, keySet).
func (v *JWTValidator) parseAndValidate(ctx context.Context, tokenStr string, keySet jwk.Set) (*SessionClaims, error) {
	opts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(v.cfg.ClockSkew),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithContext(ctx),
	}

	tok, err := jwt.ParseString(tokenStr, opts...)
	if err != nil {
		return nil, fmt.Errorf("jwt: validation failed: %w", err)
	}

	// Extract required claim: sub.
	// In jwx/v3.1.1, Subject() returns (string, bool).
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("jwt: missing required claim 'sub'")
	}

	// Extract required claim: jti.
	// In jwx/v3.1.1, JwtID() returns (string, bool).
	jti, ok := tok.JwtID()
	if !ok || jti == "" {
		return nil, fmt.Errorf("jwt: missing required claim 'jti'")
	}

	// Extract allowed_schemas.
	// In jwx/v3.1.1, Get(key, &dst) writes into dst and returns error.
	// After JSON round-trip, a []string private claim comes back as []interface{}.
	if !tok.Has("allowed_schemas") {
		return nil, fmt.Errorf("jwt: missing required claim 'allowed_schemas'")
	}
	var rawSchemas interface{}
	if getErr := tok.Get("allowed_schemas", &rawSchemas); getErr != nil {
		return nil, fmt.Errorf("jwt: could not read 'allowed_schemas': %w", getErr)
	}

	allowedSchemas, convErr := toStringSlice(rawSchemas)
	if convErr != nil {
		return nil, fmt.Errorf("jwt: 'allowed_schemas' invalid: %w", convErr)
	}
	if len(allowedSchemas) == 0 {
		return nil, fmt.Errorf("jwt: 'allowed_schemas' is empty")
	}

	// Extract issuer and audience for SessionClaims.
	// In jwx/v3.1.1, Issuer() returns (string, bool) and Audience() returns ([]string, bool).
	iss, _ := tok.Issuer()
	aud := ""
	if auds, ok := tok.Audience(); ok && len(auds) > 0 {
		aud = auds[0]
	}

	return &SessionClaims{
		Sub:            sub,
		AllowedSchemas: allowedSchemas,
		Issuer:         iss,
		Audience:       aud,
		JTI:            jti,
	}, nil
}

// toStringSlice converts an interface{} that is either []string or []interface{}
// (as returned after JSON round-trip) into a []string. Returns an error if the
// value is not a supported slice type.
func toStringSlice(v interface{}) ([]string, error) {
	switch s := v.(type) {
	case []string:
		return s, nil
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, elem := range s {
			str, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("element is not a string: %v", elem)
			}
			out = append(out, str)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected type %T, want []string or []interface{}", v)
	}
}

// newHTTPRequestWithContext is a thin wrapper around http.NewRequestWithContext.
func newHTTPRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, body)
}

// defaultHTTPClient returns a standard HTTP client with a reasonable timeout.
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
