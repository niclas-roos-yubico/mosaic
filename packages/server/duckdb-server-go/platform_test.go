package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

// Unit cover for the two platform.go pieces no other test exercises directly. addLogFields is
// the one that matters: it exists so upstream's config literal stays byte-identical, and a key
// silently vanishing from it would not fail any other test in this package.
func testPlatformConfig() *platformConfig {
	jwks := "https://example.invalid/jwks"
	issuer := "https://example.invalid/platform"
	alg := "RS256"
	external := false
	noCache := false
	timeout := 30 * time.Second
	maxBytes := int64(64 << 20)
	fd := -1
	return &platformConfig{
		jwksURL: &jwks, jwtIssuer: &issuer, jwtAlgorithm: &alg,
		enableExternalAccess: &external, disableResultCache: &noCache,
		transactionTimeout: &timeout, maxQueryResultBytes: &maxBytes, quackBootstrapFD: &fd,
	}
}

func TestAddLogFieldsCarriesEveryHardenedKeyAndNoSecret(t *testing.T) {
	p := testPlatformConfig()
	fd := 7
	p.quackBootstrapFD = &fd

	config := map[string]interface{}{"database": ":memory:"}
	p.addLogFields(config, true)

	require.Equal(t, false, config["external_access_enabled"])
	require.Equal(t, false, config["result_cache_disabled"])
	require.Equal(t, "30s", config["query_transaction_timeout"])
	require.Equal(t, int64(64<<20), config["max_query_result_bytes"])
	require.Equal(t, true, config["quack_bootstrap_started"])
	require.Equal(t, ":memory:", config["database"], "upstream's own keys must survive untouched")

	// The descriptor number itself is never logged, only whether the bootstrap ran.
	require.NotContains(t, config, "quack_bootstrap_fd")
	for key, value := range config {
		require.NotEqual(t, 7, value, "descriptor number leaked into %q", key)
	}
}

// A configured descriptor whose bootstrap did not run must log false. The old key was derived from
// the flag, so a dropped quack-bootstrap hook logged `true` for a Quack that was never started --
// the only signal an operator had, and it pointed the wrong way.
func TestAddLogFieldsReportsTheOutcomeNotTheFlag(t *testing.T) {
	p := testPlatformConfig()
	fd := 7
	p.quackBootstrapFD = &fd

	config := map[string]interface{}{}
	p.addLogFields(config, false)

	require.Equal(t, false, config["quack_bootstrap_started"],
		"the descriptor is configured but quack_serve never ran; logging true here is how a dropped "+
			"hook stays invisible")
}

// applyQueryOptions resolves a slice of option funcs into the Options value they produce, so the
// tests below can assert on the security properties themselves rather than on how many option funcs
// happen to be in the slice. A length assertion passes when a hardened option is swapped for an
// unrelated one, and fails when an unrelated option is added -- both the wrong way round.
//
// A zero Options is a faithful starting point: query.New seeds MaxConnections, MaxCacheEntries and
// Logger before applying options, and none of the fields queryOptions touches is among them.
func applyQueryOptions(t *testing.T, funcs []query.OptionFunc) *query.Options {
	t.Helper()
	options := &query.Options{}
	for _, apply := range funcs {
		require.NoError(t, apply(options))
	}
	return options
}

func TestQueryOptionsGateOnTheirFlags(t *testing.T) {
	p := testPlatformConfig()

	options := applyQueryOptions(t, p.queryOptions(nil))
	require.NotNil(t, options.FunctionAllowlist,
		"the reviewed function allowlist must be unconditional; a nil FunctionAllowlist leaves every DuckDB function callable")
	require.False(t, options.FunctionAllowlist.DisableDefaults,
		"the reviewed defaults from functionset.DefaultFunctions must stay on")
	require.True(t, options.RejectRemoteURILiterals,
		"remote-URI-literal rejection must be unconditional, not tied to a flag")
	require.False(t, options.DisableResultCache,
		"default mode keeps upstream's result cache")
	require.Nil(t, options.Transaction,
		"the transactional catalog guard belongs to external-access mode only")

	include := []string{"read_parquet"}
	options = applyQueryOptions(t, p.queryOptions(include))
	require.Equal(t, include, options.FunctionAllowlist.Include,
		"operator-supplied --function-allowlist names must reach the allowlist option")
	require.True(t, options.RejectRemoteURILiterals,
		"remote-URI-literal rejection must not depend on the allowlist argument")

	external, noCache := true, true
	p.enableExternalAccess, p.disableResultCache = &external, &noCache

	options = applyQueryOptions(t, p.queryOptions(nil))
	require.NotNil(t, options.FunctionAllowlist,
		"the reviewed function allowlist stays unconditional in external-access mode")
	require.True(t, options.RejectRemoteURILiterals,
		"remote-URI-literal rejection stays unconditional in external-access mode")
	require.True(t, options.DisableResultCache,
		"external-access mode must never serve a cached, pre-authorization result")
	require.NotNil(t, options.Transaction,
		"external-access mode must run every query under the transactional catalog guard")
	require.Equal(t, 30*time.Second, options.Transaction.Timeout,
		"the guard's deadline must come from --query-transaction-timeout")
	require.Equal(t, int64(64<<20), options.Transaction.MaxResultBytes,
		"the guard's byte cap must come from --max-query-result-bytes")
}

// Source guard for main.go's hooks.
//
// Thinning bought main.go's clean merge by making every fork edit textually disjoint from the
// upstream code it modifies. That is exactly what makes a hook deletable: a resolver reading
// `queryOptions = append(queryOptions, platform.queryOptions(...)...)` in isolation has nothing
// telling them it is load-bearing. Eight of the thirteen slugs fail the build or an existing test
// when deleted. Five do not -- they compile, the suite stays green, and the data plane silently
// loses a control:
//
//	query-options-hardened       the unconditional function allowlist and remote-URI-literal rejection
//	external-access-latch        DuckDB external access stays on in default mode
//	exec-denial-authorizer       exec gate 1
//	exec-denial-schema-resolver  exec gate 2, and pkg/server/server.go's CommandExec guard goes false,
//	                             which re-enables exec entirely
//	quack-bootstrap              Quack never starts; found 2026-08-27, after this comment had claimed
//	                             four for long enough to be believed. The count is not the point --
//	                             it was wrong once and may be wrong again. Delete a hook and boot the
//	                             binary before trusting any line of this list.
//
// Asserting only that the `FORK[<slug>]` marker survives is not enough for those: four of them
// carry their marker on its own line above the statement, so the statement can be deleted while the
// comment stays. Each entry therefore also pins a distinctive substring of the load-bearing code.
const mainGoPath = "main.go"

// mainGoSlugs is every FORK slug main.go carries. It also mechanises the AGENTS.md PR-checklist item
// "every new marker has a slug and a row in fork-inventory.json" -- see
// TestForkInventoryAndMainGoAgreeOnSlugs.
var mainGoSlugs = []string{
	"jwt-auth-import",
	"platform-flags",
	"startup-validation",
	"extension-initializer",
	"query-options-hardened",
	"external-access-latch",
	"quack-bootstrap",
	"jwt-validator",
	"exec-denial-authorizer",
	"exec-denial-schema-resolver",
	"session-middleware",
	"redacted-startup-log",
	"listener-serves-middleware",
}

// mainGoHookCode pins the code a marker cannot vouch for. Covers the four hooks whose deletion no
// other check catches, plus the two remaining security boundaries whose absence should be red on its
// own terms rather than via a build error somewhere else.
var mainGoHookCode = []struct {
	slug string
	code string
	lost string
}{
	{"startup-validation", "platform.validate(", "the fail-fast rejection of unsafe flag combinations"},
	{"query-options-hardened", "platform.queryOptions(", "the unconditional function allowlist and remote-URI-literal rejection"},
	{"external-access-latch", "platform.latchExternalAccess(", "the external-access latch; DuckDB external access stays on in default mode"},
	{"quack-bootstrap", "startQuackIfConfigured(", "the Quack bootstrap; quack_serve never runs, the mirror deployment has no Quack listener, and nothing is logged"},
	{"exec-denial-authorizer", "platformauth.Authorizer()", "exec-denial gate 1"},
	{"exec-denial-schema-resolver", "platformauth.SchemaResolver()", "exec-denial gate 2, which also flips pkg/server's CommandExec guard false and re-enables exec"},
	{"session-middleware", "platformauth.Middleware(", "platform-session JWT validation on every request"},
}

func readMainGo(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile(mainGoPath)
	require.NoError(t, err)
	return string(payload)
}

func TestMainGoRetainsEveryForkMarker(t *testing.T) {
	source := readMainGo(t)
	for _, slug := range mainGoSlugs {
		// require.True, not require.Contains: Contains renders the whole of main.go into the failure
		// output and buries the message that says what was lost.
		require.True(t, strings.Contains(source, "FORK["+slug+"]"),
			"main.go lost the %q hook marker; a merge resolution dropped a fork modification, "+
				"and either the hook must come back or its fork-inventory.json row must go", slug)
	}
}

func TestMainGoRetainsLoadBearingHookCode(t *testing.T) {
	source := readMainGo(t)
	for _, hook := range mainGoHookCode {
		require.True(t, strings.Contains(source, hook.code),
			"main.go no longer calls %s: the %q hook is gone and with it %s. "+
				"This compiles and every other test still passes -- restore the call",
			hook.code, hook.slug, hook.lost)
	}
}

// TestMainGoLatchesExternalAccessBeforeTheListener pins the latch's remaining ordering bound in
// source. platform#azfv moved the call down past upstream's db.GetExtensions, which reads the
// extension directory and so cannot run latched -- which also moved it to within a few lines of
// http.ListenAndServe, where "before any query-serving connection" stops being self-evident from
// reading run() top to bottom. TestBinaryBootsInDefaultMode covers the lower bound (too early and
// the process exits 1); this covers the upper one (too late and the data plane serves unlatched).
func TestMainGoLatchesExternalAccessBeforeTheListener(t *testing.T) {
	source := readMainGo(t)
	latch := strings.Index(source, "platform.latchExternalAccess(")
	require.NotEqual(t, -1, latch, "the external-access latch call is gone from main.go")
	listener := strings.Index(source, "http.ListenAndServe")
	require.NotEqual(t, -1, listener, "main.go no longer starts a listener; this guard cannot mean anything")
	require.Less(t, latch, listener,
		"main.go latches external access after starting the listener: requests can be served with DuckDB "+
			"external access still live. The latch must sit between the startup extension listing and the listener")
}

// TestForkInventoryAndMainGoAgreeOnSlugs pins the correspondence in both directions, so a hook added
// without a row, a row left behind after a hook is removed, and this file's own slug list drifting
// out of date are all red rather than silent.
func TestForkInventoryAndMainGoAgreeOnSlugs(t *testing.T) {
	payload, err := os.ReadFile("fork-inventory.json")
	require.NoError(t, err)
	var inventory struct {
		Entries []struct {
			Slug string `json:"slug"`
			File string `json:"file"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(payload, &inventory))

	var inventorySlugs []string
	for _, entry := range inventory.Entries {
		if entry.File == mainGoPath {
			inventorySlugs = append(inventorySlugs, entry.Slug)
		}
	}

	marker := regexp.MustCompile(`// FORK\[([a-z0-9-]+)\]`)
	seen := map[string]bool{}
	var sourceSlugs []string
	for _, match := range marker.FindAllStringSubmatch(readMainGo(t), -1) {
		if !seen[match[1]] {
			seen[match[1]] = true
			sourceSlugs = append(sourceSlugs, match[1])
		}
	}

	require.ElementsMatch(t, inventorySlugs, sourceSlugs,
		"main.go's FORK slugs and fork-inventory.json's main.go rows disagree; "+
			"every marker needs a row and every row needs a marker (AGENTS.md PR checklist)")
	require.ElementsMatch(t, mainGoSlugs, sourceSlugs,
		"this test's mainGoSlugs list is stale; update it deliberately, never to make a red test green")

	for _, hook := range mainGoHookCode {
		require.True(t, seen[hook.slug],
			"mainGoHookCode names %q, which main.go no longer marks", hook.slug)
	}
}
