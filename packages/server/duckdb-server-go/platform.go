package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/functionset"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/platformauth"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
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
	extensionFiles       *extensionFileFlag
	mirrorFileRoot       *string
}

// registerPlatformFlags declares the hardened-mode flags on the default FlagSet; it must be called
// before flag.Parse. platform-session-jwks-url has no safe default and validate rejects an empty
// one. The JWT audience is deliberately absent: newSessionValidator hardcodes it, so it can never
// be operator-settable.
func registerPlatformFlags() *platformConfig {
	extensionFiles := &extensionFileFlag{}
	flag.Var(extensionFiles, "load-extension-file",
		"Absolute path to a baked .duckdb_extension artifact, loaded on every connection. Repeatable; order is load order (httpfs before quack). Requires --enable-external-access=true.")
	return &platformConfig{
		extensionFiles:       extensionFiles,
		jwksURL:              flag.String("platform-session-jwks-url", "", "Platform session JWKS URL; required"),
		jwtIssuer:            flag.String("platform-jwt-iss", "https://<umbrella-host>/platform", "Expected Platform session JWT issuer"),
		jwtAlgorithm:         flag.String("platform-jwt-alg", "RS256", "Allowed Platform session JWT signing algorithm"),
		enableExternalAccess: flag.Bool("enable-external-access", false, "Keep DuckDB external access enabled; activates the transactional catalog guard"),
		disableResultCache:   flag.Bool("disable-result-cache", false, "Disable the server-side persisted SQL result cache"),
		transactionTimeout:   flag.Duration("query-transaction-timeout", 30*time.Second, "Maximum guarded query duration including pool wait and materialization"),
		maxQueryResultBytes:  flag.Int64("max-query-result-bytes", 64<<20, "Maximum encoded JSON or Arrow response bytes"),
		quackBootstrapFD:     flag.Int("quack-bootstrap-fd", -1, "Inherited descriptor carrying versioned Quack bootstrap config; -1 disables"),
		mirrorFileRoot:       flag.String("mirror-file-root", "", "Prefix a platform-authored VIEW body may read Parquet from, e.g. gs://bucket/mirrors. Empty refuses every view; requires --enable-external-access=true"),
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
	// LOAD by absolute path is refused once external access is latched off ("Loading external
	// extensions is disabled through configuration"), and the initializer fires on every physical
	// connection -- including pool growth long after the latch. Allowing this flag in default mode
	// would therefore work at startup and then fail the first connection opened after the latch,
	// which is a far worse failure than refusing the combination here.
	case len(p.extensionFiles.paths()) > 0 && !*p.enableExternalAccess:
		reason = "--load-extension-file requires --enable-external-access=true"
	case *p.enableExternalAccess && !*p.disableResultCache:
		reason = "--enable-external-access=true requires --disable-result-cache=true"
	// Two-tier validation runs inside the guarded transaction, and the guard is only armed in
	// external-access mode. Accepting the root without it would configure a check that silently
	// never runs -- the operator would believe views were bounded to a prefix when in fact every
	// view is still refused, and a later flag change would quietly widen the boundary.
	case *p.mirrorFileRoot != "" && !*p.enableExternalAccess:
		reason = "--mirror-file-root requires --enable-external-access=true"
		// The root's SHAPE is not checked here. query.validateGuardedOptions owns it, because a root that
		// bounds nothing is a property of the root itself and the query package is what relies on it --
		// duplicating the predicate here is how the two drift. New still runs before any resource is
		// allocated, so a bad root is a boot failure either way.
	case *p.transactionTimeout <= 0:
		reason = "--query-transaction-timeout must be positive"
	case *p.maxQueryResultBytes <= 0:
		reason = "--max-query-result-bytes must be positive"
	case strings.TrimSpace(functionBlocklistStr) != "":
		reason = "function blocklist is not permitted; use the reviewed allowlist"
	case strings.TrimSpace(schemaMatchHeadersStr) != "":
		reason = "--schema-match-headers is not permitted; schemas are derived from the validated session JWT"
	default:
		// Path-shape checks produce their own message rather than a fixed reason string.
		if fileErr := validateExtensionFiles(p.extensionFiles.paths()); fileErr != nil {
			err := fmt.Errorf("main: %w", fileErr)
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		return nil
	}
	err := fmt.Errorf("main: %s", reason)
	fmt.Fprintln(os.Stderr, err)
	return err
}

// queryOptions returns the data plane's query options. run() appends them after upstream's own
// assembly, which makes the reviewed function allowlist and remote-URI-literal rejection
// unconditional rather than opt-in: an omitted --function-allowlist leaves Include nil, and
// query.resolveFunctionAllowlist still applies functionset.DefaultFunctions. When
// --function-allowlist was passed, upstream already appended an identical WithFunctionAllowlist;
// option funcs are last-write-wins over Options.FunctionAllowlist, so the duplicate is a no-op and
// ours -- appended last -- is the one that lands.
//
// Exclude drops every Quack name from the user-facing allowlist (kata platform#qt3y). functionset
// lists Quack in coreExtensions, so its `compute` inventory -- quack_check_token,
// quack_nop_authorization, quack_uri_parser -- otherwise flows into DefaultFunctions() and is
// callable from an ordinary browser query. quack_check_token in particular is a token oracle for the
// privileged loopback write channel; a 32-byte random token makes it unguessable, but the channel is
// deliberately kept off the public query path and an oracle on it does not belong there either.
// Excluding Quack.All() rather than the three names by hand means an upstream addition to either
// bucket is covered without anyone noticing it needs to be. Exclude is applied last inside
// resolveFunctionAllowlist, so an operator cannot re-add a Quack name via --function-allowlist.
func (p *platformConfig) queryOptions(allowlistInclude []string) []query.OptionFunc {
	options := []query.OptionFunc{
		query.WithFunctionAllowlist(query.FunctionAllowlistOptions{
			Include: allowlistInclude,
			Exclude: functionset.Quack.All(),
		}),
		query.WithRemoteURILiteralRejection(),
	}
	if *p.disableResultCache {
		options = append(options, query.WithResultCacheDisabled())
	}
	if *p.enableExternalAccess {
		options = append(options, query.WithTransactionalCatalogGuard(query.TransactionOptions{
			Timeout: *p.transactionTimeout, MaxResultBytes: *p.maxQueryResultBytes,
			MirrorFileRoot: *p.mirrorFileRoot,
		}))
	}
	return options
}

// latchExternalAccess drops DuckDB external access globally and irreversibly, then verifies it --
// in external-access-off mode only. Its call position in run() is the security property: it must
// fire after the install-once initializer's INSTALL (which needs external access) and before any
// query-serving connection is opened. Quack mode requires --enable-external-access=true and is
// mutually exclusive with this path, so this is always skipped -- never entered -- when Quack is
// active. See pkg/query/external_access_global_test.go.
//
// The upper bound is not the only constraint: upstream's db.GetExtensions reads the extension
// directory off disk, so it must also run BEFORE this latch or the process exits 1 in default mode
// without ever reaching its listener (platform#azfv). Both bounds are met by calling this
// immediately after that listing. Moving it back above GetExtensions reintroduces the crash;
// TestBinaryBootsInDefaultMode is what catches that.
func (p *platformConfig) latchExternalAccess(ctx context.Context, db *query.DB, logger *slog.Logger) error {
	if *p.enableExternalAccess {
		return nil
	}
	if err := db.DisableExternalAccess(ctx); err != nil {
		logger.Error("main: failed to latch external access", "error", err)
		return err
	}
	enabled, err := db.ExternalAccessEnabled(ctx)
	if err != nil || enabled {
		logger.Error("main: external access latch verification failed", "error", err)
		if err == nil {
			err = errors.New("main: external access still enabled after latch")
		}
		return err
	}
	return nil
}

// addLogFields adds the hardened-mode fields to upstream's startup config map: booleans and numeric
// limits only, never the Quack descriptor number, the bootstrap token or payload, or
// X-Platform-Session. It exists so upstream's map literal stays byte-identical -- inlining these
// keys pushed gofmt's alignment column out past upstream's longest 20-character key and rewrote all
// 14 of its rows, which cost 14 deletions on the fork's highest-churn file.
//
// quackStarted is the OUTCOME reported by startQuackIfConfigured, not the flag. It is a parameter
// rather than a read of p.quackBootstrapFD because the two can disagree: a merge that drops the
// quack-bootstrap hook leaves the descriptor flag set while nothing ever calls quack_serve, and the
// old flag-derived key logged `true` for a Quack that was not running. Measured 2026-08-27 by
// deleting the hook and booting the binary: the port was closed, no error was logged, and this line
// was the only thing an operator had to go on. Never derive it from the flag again.
func (p *platformConfig) addLogFields(config map[string]interface{}, quackStarted bool) {
	config["external_access_enabled"] = *p.enableExternalAccess
	config["result_cache_disabled"] = *p.disableResultCache
	config["query_transaction_timeout"] = p.transactionTimeout.String()
	config["max_query_result_bytes"] = *p.maxQueryResultBytes
	config["quack_bootstrap_started"] = quackStarted
	// The root itself, not a boolean: an operator diagnosing a refused view needs to see which prefix
	// the binary is actually enforcing, and it is a configured path, not a credential.
	config["mirror_file_root"] = *p.mirrorFileRoot
}

// newSessionValidator builds the platform session JWT validator. The audience is hardcoded to
// "platform-data-plane" and is deliberately not a flag, so it can never be operator-settable.
func (p *platformConfig) newSessionValidator(logger *slog.Logger) (*platformauth.JWTValidator, error) {
	validator, err := platformauth.NewJWTValidator(platformauth.JWTValidatorConfig{
		JWKSURL: *p.jwksURL, Issuer: *p.jwtIssuer,
		Audience: "platform-data-plane", Algorithms: []string{*p.jwtAlgorithm},
	})
	if err != nil {
		logger.Error("main: error creating platform session validator", "error", err)
		return nil, err
	}
	return validator, nil
}
