package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// platformConfig owns every flag, validation and construction step the platform data plane adds to
// upstream's run(). It exists so main.go carries call positions only: where each of these fires in
// the startup sequence is a security property and has to stay visible in upstream's file, but the
// bodies do not -- see AGENTS.md rules 3 and 4.
type platformConfig struct {
	jwksURL              *string
	jwtIssuer            *string
	jwtAlgorithm         *string
	enableExternalAccess *bool
	disableResultCache   *bool
	transactionTimeout   *time.Duration
	maxQueryResultBytes  *int64
	quackBootstrapFD     *int
}

// registerPlatformFlags declares the hardened-mode flags on the default FlagSet; it must be called
// before flag.Parse. platform-session-jwks-url has no safe default and validate rejects an empty
// one. The JWT audience is deliberately absent: newSessionValidator hardcodes it, so it can never
// be operator-settable.
func registerPlatformFlags() *platformConfig {
	return &platformConfig{
		jwksURL:              flag.String("platform-session-jwks-url", "", "Platform session JWKS URL; required"),
		jwtIssuer:            flag.String("platform-jwt-iss", "https://<umbrella-host>/platform", "Expected Platform session JWT issuer"),
		jwtAlgorithm:         flag.String("platform-jwt-alg", "RS256", "Allowed Platform session JWT signing algorithm"),
		enableExternalAccess: flag.Bool("enable-external-access", false, "Keep DuckDB external access enabled; activates the transactional catalog guard"),
		disableResultCache:   flag.Bool("disable-result-cache", false, "Disable the server-side persisted SQL result cache"),
		transactionTimeout:   flag.Duration("query-transaction-timeout", 30*time.Second, "Maximum guarded query duration including pool wait and materialization"),
		maxQueryResultBytes:  flag.Int64("max-query-result-bytes", 64<<20, "Maximum encoded JSON or Arrow response bytes"),
		quackBootstrapFD:     flag.Int("quack-bootstrap-fd", -1, "Inherited descriptor carrying versioned Quack bootstrap config; -1 disables"),
	}
}

// validate runs every startup-mode check, in order, immediately after flag.Parse and before any
// resource is allocated -- no listener, connector, or JWKS fetch -- so an unsafe flag combination
// fails fast with a specific, greppable message instead of partially starting up. The order matters:
// later checks only make sense once an earlier one has passed, and main_flags_test.go asserts which
// message comes back for a given partial flag set.
//
// schemaMatchHeadersStr and functionBlocklistStr are upstream flags this binary refuses rather than
// deletes: upstream's declarations, var blocks and call sites stay byte-identical and the guarantee
// is this explicit rejection instead of an absence (kata platform#z5x2). validate prints its own
// message so the hook in run() has no body.
func (p *platformConfig) validate(schemaMatchHeadersStr, functionBlocklistStr string) error {
	var reason string
	switch {
	case *p.jwksURL == "":
		reason = "--platform-session-jwks-url is required"
	case *p.quackBootstrapFD != -1 && *p.quackBootstrapFD < 3:
		reason = "--quack-bootstrap-fd must be -1 or at least 3"
	case *p.quackBootstrapFD >= 3 && !*p.enableExternalAccess:
		reason = "--quack-bootstrap-fd requires --enable-external-access=true"
	case *p.enableExternalAccess && !*p.disableResultCache:
		reason = "--enable-external-access=true requires --disable-result-cache=true"
	case *p.transactionTimeout <= 0:
		reason = "--query-transaction-timeout must be positive"
	case *p.maxQueryResultBytes <= 0:
		reason = "--max-query-result-bytes must be positive"
	case strings.TrimSpace(functionBlocklistStr) != "":
		reason = "function blocklist is not permitted; use the reviewed allowlist"
	case strings.TrimSpace(schemaMatchHeadersStr) != "":
		reason = "--schema-match-headers is not permitted; schemas are derived from the validated session JWT"
	default:
		return nil
	}
	err := fmt.Errorf("main: %s", reason)
	fmt.Fprintln(os.Stderr, err)
	return err
}
