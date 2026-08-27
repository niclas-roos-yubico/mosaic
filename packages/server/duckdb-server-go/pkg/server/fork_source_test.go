package server

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Source guard for pkg/server's hooks, the same pattern platform_test.go applies to main.go.
//
// Measured 2026-08-27 by deleting each hook and running `go build -tags=duckdb_arrow ./...`
// then the full suite:
//
//	config-schema-resolver          build fails
//	handler-schema-resolver-field   build fails
//	handler-schema-resolver-assign  builds, suite red (schema_resolver_test.go)
//	ws-request-schemas              build fails (resolution feeds beginWebSocketSession)
//	ws-session-bounds               build fails (queryCtx unbound)
//	ws-message-query-ctx            builds, suite red
//	http-request-schemas            builds, suite red
//	exec-schema-policy-gate         builds, suite red
//	guarded-error-mapping           builds, suite red (errors_fork_test.go)
//
// So unlike main.go, no pkg/server hook's *code* can be lost silently -- every one is caught by
// the compiler or by an existing test. What can still be lost silently is the marker: two of the
// nine sit on their own line above the statement, so a resolution can drop the comment and leave
// working code with no inventory trail. TestPkgServerRetainsLoadBearingHookCode therefore pins the
// code as well as the marker, so neither half can disappear on its own.

var forkSourceFiles = []string{"server.go", "options.go", "errors.go"}

// pkgServerSlugs is every FORK slug pkg/server carries, keyed by file. It mechanises the AGENTS.md
// PR-checklist item "every new marker has a slug and a row in fork-inventory.json" -- see
// TestForkInventoryAndPkgServerAgreeOnSlugs.
var pkgServerSlugs = map[string][]string{
	"server.go": {
		"handler-schema-resolver-field",
		"handler-schema-resolver-assign",
		"ws-request-schemas",
		"ws-session-bounds",
		"ws-message-query-ctx",
		"http-request-schemas",
		"exec-schema-policy-gate",
	},
	"options.go": {"config-schema-resolver"},
	"errors.go":  {"guarded-error-mapping"},
}

// pkgServerHookCode pins the code a marker cannot vouch for. `count` is how many times the
// substring must appear: requestSchemas is called from both handlers, and asserting presence alone
// would stay green with one of the two reverted to upstream's header derivation.
var pkgServerHookCode = []struct {
	file  string
	slug  string
	code  string
	count int
	lost  string
}{
	{"server.go", "handler-schema-resolver-assign", "cfg.schemaResolver", 1,
		"the resolver never reaches the handler: requestSchemas falls back to headers and the exec gate below goes false"},
	{"server.go", "ws-request-schemas", "s.requestSchemas(r)", 2,
		"a handler derives allowed schemas from request headers instead of the validated session JWT"},
	{"server.go", "ws-session-bounds", "s.beginWebSocketSession(", 1,
		"the websocket session's expiry close, query deadline and single-source close"},
	{"server.go", "ws-message-query-ctx", "s.execCommand(queryCtx,", 1,
		"command execution is bounded by the plain network ctx, so a query outlives the session expiry"},
	{"server.go", "exec-schema-policy-gate", "if s.schemaResolver != nil {", 1,
		"exec-denial gate 3; in platform mode schemaMatchHeaders is empty, so upstream's own gate does not fire and exec is re-enabled"},
	{"errors.go", "guarded-error-mapping", "query.ErrResultTooLarge", 1,
		"byte-cap and deadline hits are classified as a generic bad_request"},
}

func readForkSource(t *testing.T, file string) string {
	t.Helper()
	payload, err := os.ReadFile(file)
	require.NoError(t, err)
	return string(payload)
}

func TestPkgServerRetainsEveryForkMarker(t *testing.T) {
	for _, file := range forkSourceFiles {
		source := readForkSource(t, file)
		for _, slug := range pkgServerSlugs[file] {
			// require.True, not require.Contains: Contains renders the whole file into the failure
			// output and buries the message that says what was lost.
			require.True(t, strings.Contains(source, "FORK["+slug+"]"),
				"%s lost the %q hook marker; a merge resolution dropped a fork modification, "+
					"and either the hook must come back or its fork-inventory.json row must go", file, slug)
		}
	}
}

func TestPkgServerRetainsLoadBearingHookCode(t *testing.T) {
	for _, hook := range pkgServerHookCode {
		got := strings.Count(readForkSource(t, hook.file), hook.code)
		require.Equal(t, hook.count, got,
			"%s has %d occurrences of %s, expected %d: the %q hook is gone and with it %s. "+
				"Restore the call -- do not adjust this expectation to make the test green",
			hook.file, got, hook.code, hook.count, hook.slug, hook.lost)
	}
}

// TestForkInventoryAndPkgServerAgreeOnSlugs pins the correspondence in both directions, so a hook
// added without a row, a row left behind after a hook is removed, and this file's own slug lists
// drifting out of date are all red rather than silent.
func TestForkInventoryAndPkgServerAgreeOnSlugs(t *testing.T) {
	payload, err := os.ReadFile("../../fork-inventory.json")
	require.NoError(t, err)
	var inventory struct {
		Entries []struct {
			Slug string `json:"slug"`
			File string `json:"file"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(payload, &inventory))

	marker := regexp.MustCompile(`// FORK\[([a-z0-9-]+)\]`)
	for _, file := range forkSourceFiles {
		var inventorySlugs []string
		for _, entry := range inventory.Entries {
			if entry.File == "pkg/server/"+file {
				inventorySlugs = append(inventorySlugs, entry.Slug)
			}
		}

		seen := map[string]bool{}
		var sourceSlugs []string
		for _, match := range marker.FindAllStringSubmatch(readForkSource(t, file), -1) {
			if !seen[match[1]] {
				seen[match[1]] = true
				sourceSlugs = append(sourceSlugs, match[1])
			}
		}

		require.ElementsMatch(t, inventorySlugs, sourceSlugs,
			"%s's FORK slugs and fork-inventory.json's rows for it disagree; "+
				"every marker needs a row and every row needs a marker (AGENTS.md PR checklist)", file)
		require.ElementsMatch(t, pkgServerSlugs[file], sourceSlugs,
			"this test's pkgServerSlugs[%q] list is stale; update it deliberately, never to make a red test green", file)
	}

	for _, hook := range pkgServerHookCode {
		require.Contains(t, pkgServerSlugs[hook.file], hook.slug,
			"pkgServerHookCode names %q, which is not in pkgServerSlugs[%q]", hook.slug, hook.file)
	}
}
