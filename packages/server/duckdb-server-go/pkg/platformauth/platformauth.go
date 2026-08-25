package platformauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/server"
)

// SessionHeader carries the Platform session JWT on every authenticated
// request. Its value must never be logged or echoed back to the client.
const SessionHeader = "X-Platform-Session"

// claimsContextKey is unexported so no package outside platformauth can
// forge SessionClaims into a request context.
type claimsContextKey struct{}

// Middleware validates the Platform session JWT carried in SessionHeader and,
// on success, stashes the resulting *SessionClaims in the request context for
// SchemaResolver to read back out. CORS preflights (OPTIONS) carry no session
// token and cannot execute a command — see server.newCORSHandler, which
// intercepts every OPTIONS request before it reaches command execution, and
// handler.handleHTTP, whose method switch only builds a command for GET/POST
// — so they are passed through unauthenticated without weakening the
// authentication boundary for any request that could run a query.
func Middleware(validator *JWTValidator, logger *slog.Logger) func(http.Handler) http.Handler {
	if validator == nil {
		panic("platformauth: JWT validator is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS preflights carry no session token and execute no command.
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			token := r.Header.Get(SessionHeader)
			if token == "" {
				writeUnauthenticated(w)
				return
			}
			claims, err := validator.Validate(r.Context(), token)
			if err != nil {
				// Log a sanitized, fixed reason code — never err.Error() or the
				// token. Most validation failures (expired, wrong iss/aud,
				// missing claims) use jwx sentinel errors whose messages never
				// interpolate claim values, but algEnforcingKeyProvider's key
				// lookup does interpolate the token header's attacker-controlled
				// "kid" verbatim (see jwt.go), so the raw error must never reach
				// a log sink or response.
				logger.WarnContext(r.Context(), "platform session rejected", "reason", classifyValidationError(err))
				writeUnauthenticated(w)
				return
			}
			ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Sanitized reason codes for a rejected session. Every value here is a
// compile-time constant string with nothing interpolated into it, so logging
// one can never leak claim values or token header fields.
const (
	reasonTokenExpired    = "token_expired"
	reasonNotYetValid     = "token_not_yet_valid"
	reasonInvalidAudience = "invalid_audience"
	reasonInvalidIssuer   = "invalid_issuer"
	reasonMissingClaim    = "missing_required_claim"
	reasonJWKSUnavailable = "jwks_unavailable"
	reasonSignatureOrKey  = "signature_or_key"
	reasonOther           = "other"
)

// classifyValidationError maps a Validate failure to one of the fixed reason
// codes above using errors.Is against jwx's sentinel errors (whose messages
// never interpolate claim values) and this package's own errJWKSUnavailable /
// errKeyOrSignature sentinels (see jwt.go), which cover the one place a
// validation error can carry attacker-controlled content — the token
// header's "kid" — so that content is classified, never formatted into a log
// line or response.
func classifyValidationError(err error) string {
	switch {
	case errors.Is(err, jwt.TokenExpiredError()):
		return reasonTokenExpired
	case errors.Is(err, jwt.TokenNotYetValidError()):
		return reasonNotYetValid
	case errors.Is(err, jwt.InvalidAudienceError()):
		return reasonInvalidAudience
	case errors.Is(err, jwt.InvalidIssuerError()):
		return reasonInvalidIssuer
	case errors.Is(err, jwt.MissingRequiredClaimError()):
		return reasonMissingClaim
	case errors.Is(err, errJWKSUnavailable):
		return reasonJWKSUnavailable
	case errors.Is(err, errKeyOrSignature):
		return reasonSignatureOrKey
	default:
		return reasonOther
	}
}

// writeUnauthenticated writes a generic rejection body. It must never include
// the submitted token, the Authorization/X-Platform-Session header value, or
// any validation error detail that could contain the token.
func writeUnauthenticated(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated"})
}

func claimsFromRequest(r *http.Request) (*SessionClaims, bool) {
	claims, ok := r.Context().Value(claimsContextKey{}).(*SessionClaims)
	return claims, ok && claims != nil
}

// SchemaResolver adapts the claims stashed by Middleware into a
// server.SchemaResolver. It fails closed: if Middleware did not run (or
// rejected the request), no claims are present in the context and
// ResolveSchemas returns server.ErrUnauthenticated rather than an
// empty-but-successful resolution.
func SchemaResolver() server.SchemaResolver {
	return server.SchemaResolverFunc(func(r *http.Request) (server.SchemaResolution, error) {
		claims, ok := claimsFromRequest(r)
		if !ok {
			return server.SchemaResolution{}, server.ErrUnauthenticated
		}
		return server.SchemaResolution{
			// Copy rather than alias claims.AllowedSchemas so callers cannot
			// mutate the backing array shared with the validated claims.
			AllowedSchemas: append([]string(nil), claims.AllowedSchemas...),
			ExpiresAt:      claims.ExpiresAt,
		}, nil
	})
}

// Authorizer denies every "exec" command. It is the first of three
// independent exec denial gates (alongside the server package's handler
// policy guard and the query package's query policy).
func Authorizer() server.Authorizer {
	return server.AuthorizerFunc(func(*http.Request) (server.CommandAuthorizer, error) {
		return func(_ context.Context, command server.Command) error {
			if command.Type() == server.CommandExec {
				return server.ErrPermissionDenied
			}
			return nil
		}, nil
	})
}
