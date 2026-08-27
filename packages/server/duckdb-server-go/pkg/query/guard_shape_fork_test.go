package query

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FORK-OWNED FILE. Permanent regression test for the *shape* of the transactional catalog guard, not for what it
// computes -- transaction_test.go and catalog_guard_test.go own that.
//
// Why this file exists. A dry run of this component (docs/superpowers/specs/
// 2026-08-26-mosaic-fork-thinning-c2-dryrun-evidence.md, Question 1) rebuilt the guard as an embedded-struct
// decorator, GuardedDB{ *DB }, to shrink query.go's diff against upstream. It shipped a cross-tenant fail-open: Go
// has no virtual dispatch, so a decorator intercepts only calls made *through* the wrapper, and -- worse -- the
// object query.New(WithTransactionalCatalogGuard(...)) hands back is the bare *DB, which every caller already holds
// unwrapped. AGENTS.md rule 4 now forbids that shape outright; the compliant form is guard state on upstream's own
// receiver (`db.transaction`), tested here.
//
// The two hazards this file is pointed at, in order of likelihood:
//
//  1. A future upstream commit adds a *DB-internal call to one of the entry points -- deduping WriteJSON onto
//     QueryJSON, or adding a QueryCSV that reuses QueryArrow. Both are ordinary refactors; both merge cleanly,
//     compile, and pass every other test with a decorator's guard silently bypassed. There are zero such internal
//     callers today, so this file supplies its own (the simulatedUpstream* methods below) rather than enumerating
//     real ones.
//  2. Someone re-litigates the diff size and converts the receiver-state guard back into a wrapper type.
//
// Each assertion below is on an observable security *outcome*, never on "a function was called". A call-count
// assertion is satisfiable by a rewrite that has lost the guarantee; a denied query is not.

// ---------------------------------------------------------------------------
// Simulated future upstream refactors.
//
// These are written as methods on *DB because that is where upstream would write them: internal reuse of a public
// entry point. They are the whole point of the file -- they are the dispatch path that a wrapper type cannot see.
// ---------------------------------------------------------------------------

// simulatedUpstreamWriteJSONViaQueryJSON models the single most plausible upstream refactor: WriteJSON and QueryJSON
// share their entire body except the buffer, so deduping one onto the other is a benign-looking change.
func (db *DB) simulatedUpstreamWriteJSONViaQueryJSON(ctx context.Context, statement string, allowedSchemas []string, w io.Writer) error {
	data, _, err := db.QueryJSON(ctx, statement, allowedSchemas, false)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// simulatedUpstreamQueryCSVViaQueryArrow models a new output format added upstream on top of an existing one.
func (db *DB) simulatedUpstreamQueryCSVViaQueryArrow(ctx context.Context, statement string, allowedSchemas []string, w io.Writer) error {
	data, _, err := db.QueryArrow(ctx, statement, allowedSchemas, false)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// simulatedUpstreamStreamJSONViaWriteJSON and its Arrow twin cover the two entry points that have no non-test caller
// anywhere in the fork today (they sit outside pkg/server's commandExecutor seam), and so have no other guard
// against an internal caller appearing.
func (db *DB) simulatedUpstreamStreamJSONViaWriteJSON(ctx context.Context, statement string, allowedSchemas []string, w io.Writer) error {
	return db.WriteJSON(ctx, statement, allowedSchemas, w)
}

func (db *DB) simulatedUpstreamStreamArrowViaWriteArrow(ctx context.Context, statement string, allowedSchemas []string, w io.Writer) error {
	return db.WriteArrow(ctx, statement, allowedSchemas, w)
}

// simulatedUpstreamExecScript models upstream routing DDL through its own Exec, which must stay denied in guarded
// mode: raw exec is not validated, not catalog-checked, and not byte-capped.
func (db *DB) simulatedUpstreamExecScript(ctx context.Context, statement string) error {
	return db.Exec(ctx, statement)
}

// internalDispatchPaths is every entry point, reached from inside another *DB method. The calls are written as Go
// method expressions so the table cannot be satisfied by a free function that merely looks like the method.
var internalDispatchPaths = []struct {
	name string
	call func(db *DB, ctx context.Context, statement string, allowedSchemas []string, w io.Writer) error
}{
	{"QueryJSON", (*DB).simulatedUpstreamWriteJSONViaQueryJSON},
	{"QueryArrow", (*DB).simulatedUpstreamQueryCSVViaQueryArrow},
	{"WriteJSON", (*DB).simulatedUpstreamStreamJSONViaWriteJSON},
	{"WriteArrow", (*DB).simulatedUpstreamStreamArrowViaWriteArrow},
}

const (
	guardShapeSeed = `CREATE SCHEMA other_tenant;
CREATE TABLE other_tenant.secret(value VARCHAR);
INSERT INTO other_tenant.secret VALUES ('other-tenant-secret')`
	guardShapeQuery  = `SELECT * FROM other_tenant.secret`
	guardShapeSecret = "other-tenant-secret"
)

// TestGuardIsReachedThroughDBInternalDispatch is the finding from the dry run, inverted into an assertion on the
// shipped shape.
//
// The probe uses an EMPTY allowed-schema list on purpose. That is the one input where the guarded and unguarded
// paths disagree about a query that is otherwise perfectly legal: newValidators only installs the base-table
// validator when len(allowedSchemas) > 0, and this DB configures no blocklist, no allowlist and no URI-literal
// rejection, so upstream's validateQuery builds zero validators, returns nil, and serves the row. Only
// executeGuarded's I3 check denies it. A cross-schema query would prove nothing here -- upstream's validator
// rejects that too, so it cannot tell "the guard ran" from "the guard was bypassed".
func TestGuardIsReachedThroughDBInternalDispatch(t *testing.T) {
	for _, path := range internalDispatchPaths {
		t.Run(path.name, func(t *testing.T) {
			db, _ := guardedTransactionDB(t, guardShapeSeed,
				TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

			var buf bytes.Buffer
			err := path.call(db, t.Context(), guardShapeQuery, []string{}, &buf)

			require.ErrorIs(t, err, ErrAccessDenied,
				"%s reached from inside another *DB method did not reach the guard. The guard must be state on "+
					"upstream's receiver, not a wrapper type: Go has no virtual dispatch, so a wrapper is invisible "+
					"to any call *DB makes to itself. See AGENTS.md rule 4.", path.name)
			require.NotContains(t, buf.String(), guardShapeSecret,
				"%s served a row from an unauthorized schema with an empty allowed-schema list -- this is the "+
					"cross-tenant fail-open the dry run shipped", path.name)
		})
	}
}

// TestGuardedExecIsDeniedThroughInternalDispatch covers the fifth marked site. Exec's guarded term is a gate, not a
// route, so its observable outcome is the denial itself.
func TestGuardedExecIsDeniedThroughInternalDispatch(t *testing.T) {
	db, _ := guardedTransactionDB(t, guardShapeSeed,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

	require.ErrorIs(t, db.simulatedUpstreamExecScript(t.Context(), `CREATE SCHEMA smuggled`), ErrExecWithValidation,
		"guarded mode's exec gate must deny raw exec for every holder of the *DB, including an internal caller: "+
			"raw exec is neither validated, catalog-checked, nor byte-capped")
}

// TestConstructorCannotHandOutABypassableDB pins failure B from the dry run, which needs no future upstream commit
// at all: under a decorator, query.New returns the unguarded *DB and every caller in the program is already holding
// it. Here the object New returns is asserted to be guarded on every entry point, directly.
func TestConstructorCannotHandOutABypassableDB(t *testing.T) {
	db, _ := guardedTransactionDB(t, guardShapeSeed,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

	require.NotNil(t, db.transaction,
		"New must arm the guard on the very object it returns; guard state on upstream's receiver is what makes "+
			"that possible, and is why the guard is not a type applied on top after construction")

	jsonData, _, err := db.QueryJSON(t.Context(), guardShapeQuery, []string{}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.NotContains(t, string(jsonData), guardShapeSecret)

	arrowData, _, err := db.QueryArrow(t.Context(), guardShapeQuery, []string{}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Empty(t, arrowData)

	var jsonBuf bytes.Buffer
	require.ErrorIs(t, db.WriteJSON(t.Context(), guardShapeQuery, []string{}, &jsonBuf), ErrAccessDenied)
	require.Empty(t, jsonBuf.String())

	var arrowBuf bytes.Buffer
	require.ErrorIs(t, db.WriteArrow(t.Context(), guardShapeQuery, []string{}, &arrowBuf), ErrAccessDenied)
	require.Empty(t, arrowBuf.String())

	require.ErrorIs(t, db.Exec(t.Context(), `CREATE SCHEMA smuggled`), ErrExecWithValidation)
}

// TestGuardedByteCapAppliesToEveryEntryPoint is a second, independent effect that only the guarded path can produce:
// upstream's path has no byte cap at all. It is asserted on an AUTHORIZED query, so it cannot be satisfied by
// validation alone -- the request must have travelled through executeGuarded's limitedBuffer. This is what keeps the
// previous tests honest if someone ever reintroduces a validator-only shortcut in front of the route decision.
func TestGuardedByteCapAppliesToEveryEntryPoint(t *testing.T) {
	authorized := []string{"other_tenant"}

	db, _ := guardedTransactionDB(t, guardShapeSeed,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 4})

	_, _, err := db.QueryJSON(t.Context(), guardShapeQuery, authorized, false)
	require.ErrorIs(t, err, ErrResultTooLarge)

	_, _, err = db.QueryArrow(t.Context(), guardShapeQuery, authorized, false)
	require.ErrorIs(t, err, ErrResultTooLarge)

	var jsonBuf bytes.Buffer
	require.ErrorIs(t, db.WriteJSON(t.Context(), guardShapeQuery, authorized, &jsonBuf), ErrResultTooLarge)
	require.Empty(t, jsonBuf.String(), "no byte may reach the writer from a transaction that did not commit")

	var arrowBuf bytes.Buffer
	require.ErrorIs(t, db.WriteArrow(t.Context(), guardShapeQuery, authorized, &arrowBuf), ErrResultTooLarge)
	require.Empty(t, arrowBuf.String(), "no byte may reach the writer from a transaction that did not commit")
}

// ---------------------------------------------------------------------------
// Source guard for query.go's five rule-4 exceptions.
//
// The runtime tests above catch a guard that stops working. This catches a guard that is quietly *removed* by a
// merge resolution -- which, per the AGENTS.md sync runbook, is zero-conflict, compiles, and would leave the tests
// above red only because the deletion also breaks them. Marker-only assertions are not enough (the marker can
// survive the statement it sits above), so each site also pins the load-bearing code, scoped to the function that
// must contain it rather than to the file as a whole.
// ---------------------------------------------------------------------------

const queryGoPath = "query.go"

var queryGoGuardSites = []struct {
	slug      string
	signature string
	code      []string
	lost      string
}{
	{
		slug:      "exec-denial-guarded",
		signature: "func (db *DB) Exec(",
		code:      []string{"db.transaction != nil ||"},
		lost:      "exec gate 3; raw exec bypasses validation, the live catalog check and the byte cap entirely",
	},
	{
		slug:      "guarded-route-queryjson",
		signature: "func (db *DB) QueryJSON(",
		code:      []string{"if db.transaction != nil {", "db.guardedJSON("},
		lost:      "the guarded route for QueryJSON, the entry point pkg/server's HTTP and WebSocket JSON path uses",
	},
	{
		slug:      "guarded-route-writejson",
		signature: "func (db *DB) WriteJSON(",
		code:      []string{"if db.transaction != nil {", "db.writeGuarded(", "responseJSON"},
		lost:      "the guarded route for WriteJSON",
	},
	{
		slug:      "guarded-route-queryarrow",
		signature: "func (db *DB) QueryArrow(",
		code:      []string{"if db.transaction != nil {", "db.guardedArrow("},
		lost:      "the guarded route for QueryArrow, the entry point pkg/server's Arrow path uses",
	},
	{
		slug:      "guarded-route-writearrow",
		signature: "func (db *DB) WriteArrow(",
		code:      []string{"if db.transaction != nil {", "db.writeGuarded(", "responseArrow"},
		lost:      "the guarded route for WriteArrow",
	},
}

func readQueryGo(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile(queryGoPath)
	require.NoError(t, err)
	return string(payload)
}

// functionBody returns the source of the declaration starting at signature, up to the next top-level func.
func functionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	// require.True, not require.Contains: Contains renders the whole of query.go into the failure output.
	require.True(t, start >= 0, "query.go no longer declares %s", signature)
	rest := source[start+len(signature):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		return rest[:end]
	}
	return rest
}

func TestQueryGoRetainsEveryGuardRouteMarker(t *testing.T) {
	source := readQueryGo(t)
	for _, site := range queryGoGuardSites {
		require.True(t, strings.Contains(source, "FORK["+site.slug+"]"),
			"query.go lost the %q marker; a merge resolution dropped a fork modification, and either the hook "+
				"must come back or its fork-inventory.json row must go", site.slug)
	}
}

func TestQueryGoRetainsTheRouteDecisionOnTheReceiver(t *testing.T) {
	source := readQueryGo(t)
	for _, site := range queryGoGuardSites {
		body := functionBody(t, source, site.signature)
		for _, code := range site.code {
			require.True(t, strings.Contains(body, code),
				"%s no longer contains %q: the %q hook is gone and with it %s.\n\n"+
					"The route decision has to stay HERE, on upstream's receiver, even though its body lives in "+
					"guarded.go. Moving the decision onto a wrapper type is the shape AGENTS.md rule 4 forbids: it "+
					"is bypassed by any call *DB makes to itself and by New's own return value.",
				site.signature, code, site.slug, site.lost)
		}
	}
}

// ---------------------------------------------------------------------------
// Source guard for New's four constructor hooks.
//
// Measured, not assumed. Each of the four lines below was deleted in turn, the module rebuilt and the whole suite
// re-run (Task 4, 2026-08-27). `go build -tags=duckdb_arrow ./...` stayed green for ALL FOUR -- the compiler catches
// none of them, which is exactly the hazard the sync runbook warns about. Three were already caught at runtime:
//
//	transaction: o.Transaction      -> 11 tests red (the guard is disarmed package-wide)
//	arrowPool:   newArrowPool(...)  -> 2 tests red (nil pool on the guarded path)
//	validateGuardedOptions(o)       -> 1 test red (options_test.go)
//	discardCacheIfDisabled(cache,o) -> NOTHING. Whole suite green with the hook gone.
//
// That last one is why this table exists. Losing it re-arms the cache read inside executeGuarded that transaction.go
// documents as unreachable-by-construction, on a key derived from (format, statement) with no tenant or schema
// dimension -- and no other check in the repository would say a word.
//
// A synthetic merge probe (Task 4) reproduced exactly that: an upstream commit renaming New's `cache` local to
// `resultCache` merges into this branch with ZERO conflicts, leaves `discardCacheIfDisabled(cache, o)` dangling, and
// the naive resolution -- delete the line that will not compile -- builds green. This table is the only thing that
// goes red on it. The pins below therefore match the fork-owned CALLEE name, not the upstream argument names, so
// that re-pointing a hook at a renamed upstream local (the CORRECT resolution) stays green while deleting the hook
// does not.
// ---------------------------------------------------------------------------

var queryGoConstructorSites = []struct {
	slug string
	code string
	lost string
}{
	{
		slug: "guarded-option-validation",
		code: "validateGuardedOptions(",
		lost: "the pre-allocation rejection of unsafe guarded configurations; New would accept a zero timeout, " +
			"a zero byte cap, or the result cache left enabled alongside the guard",
	},
	{
		slug: "result-cache-discard",
		code: "discardCacheIfDisabled(",
		lost: "the only thing that makes db.cache nil in guarded mode; executeGuarded's cache read stops being " +
			"unreachable-by-construction and starts keying guarded responses on (format, statement) alone",
	},
	{
		slug: "guarded-state-field",
		code: "transaction: o.Transaction",
		lost: "the guard state itself; every route prelude then sees a nil db.transaction and falls through to " +
			"upstream's unvalidated path, with the catalog guard silently disarmed",
	},
	{
		slug: "arrow-pool-field",
		code: "newArrowPool(",
		lost: "the conn-paired Arrow pool the guarded coordinator acquires from",
	},
}

func TestQueryGoRetainsNewConstructorHooks(t *testing.T) {
	body := functionBody(t, readQueryGo(t), "func New(")
	for _, site := range queryGoConstructorSites {
		require.True(t, strings.Contains(body, site.code),
			"query.go's New no longer contains %q: the %q hook is gone and with it %s.\n\n"+
				"This compiles, and outside this file almost nothing else goes red.\n\n"+
				"If upstream renamed something this hook names, RE-POINT the hook at the new name. Never delete "+
				"it as unused leftover -- that is the fail-open this test exists to stop.",
			site.code, site.slug, site.lost)
		require.True(t, strings.Contains(body, "FORK["+site.slug+"]"),
			"query.go's New lost the %q marker; either the hook must come back or its fork-inventory.json "+
				"row must go (AGENTS.md PR checklist)", site.slug)
	}
}

// TestForkInventoryAndPkgQueryAgreeOnSlugs pins the correspondence in both directions for every upstream-owned,
// non-test file in pkg/query -- the analogue of platform_test.go's TestForkInventoryAndMainGoAgreeOnSlugs, which
// covered only main.go. Before this existed, 25 of pkg/query's 28 inventory rows had rotted into orphans across
// Tasks 2 and 3 with nothing to say so. A hook added without a row, a row left behind after a hook is removed, an
// unslugged `// FORK:` marker, and a slug reused across two files are all red here rather than silent.
func TestForkInventoryAndPkgQueryAgreeOnSlugs(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "fork-inventory.json"))
	require.NoError(t, err)
	var inventory struct {
		Entries []struct {
			Slug string `json:"slug"`
			File string `json:"file"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(payload, &inventory))

	sources, err := filepath.Glob("*.go")
	require.NoError(t, err)

	marker := regexp.MustCompile(`// FORK\[([a-z0-9-]+)\]`)
	slugOwner := map[string]string{}
	visited := map[string]bool{}

	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		visited["pkg/query/"+source] = true
		payload, err := os.ReadFile(source)
		require.NoError(t, err)
		body := string(payload)

		// An unslugged marker is invisible to every check keyed on slugs, so it has to be caught here.
		// require.False, not require.NotContains: NotContains renders the whole source file into the failure
		// output and buries the message that says what is wrong.
		require.False(t, strings.Contains(body, "// FORK:"),
			"%s carries an unslugged // FORK: marker. Give it a slug and a fork-inventory.json row; retiring "+
				"the row instead would delete the record of a real fork modification", source)

		seen := map[string]bool{}
		var sourceSlugs []string
		for _, match := range marker.FindAllStringSubmatch(body, -1) {
			if !seen[match[1]] {
				seen[match[1]] = true
				sourceSlugs = append(sourceSlugs, match[1])
			}
			if owner, ok := slugOwner[match[1]]; ok && owner != source {
				require.Fail(t, "slug reused across files",
					"slug %q appears in both %s and %s. AGENTS.md requires a slug to be unique in the "+
						"package: one logical modification spanning two files gets one slug PER FILE, never "+
						"one slug on two rows (see exec-denial-authorizer / exec-denial-schema-resolver)",
					match[1], owner, source)
			}
			slugOwner[match[1]] = source
		}

		var inventorySlugs []string
		for _, entry := range inventory.Entries {
			if entry.File == path.Join("pkg", "query", source) {
				inventorySlugs = append(inventorySlugs, entry.Slug)
			}
		}

		require.ElementsMatch(t, inventorySlugs, sourceSlugs,
			"%s's FORK slugs and its fork-inventory.json rows disagree; every marker needs a row and every "+
				"row needs a marker (AGENTS.md PR checklist)", source)
	}

	// The loop above only visits non-test sources that exist on disk, so a row naming a deleted path -- or a
	// _test.go path, which the marker audit deliberately excludes -- would never be reached by the direction-B
	// check and would sit in the inventory unnoticed. Close that here.
	for _, entry := range inventory.Entries {
		if !strings.HasPrefix(entry.File, "pkg/query/") {
			continue
		}
		require.True(t, visited[entry.File],
			"fork-inventory.json row %q names %q, which is not a non-test source file in pkg/query; either the "+
				"file was deleted and the row should go, or the row points at a _test.go path the marker audit "+
				"does not cover", entry.Slug, entry.File)
	}

	// Keep this file's own source-guard tables from drifting out of date silently.
	var guarded []string
	for _, site := range queryGoGuardSites {
		guarded = append(guarded, site.slug)
	}
	for _, site := range queryGoConstructorSites {
		guarded = append(guarded, site.slug)
	}
	for _, slug := range guarded {
		require.Contains(t, slugOwner, slug,
			"this file's source-guard tables name %q, which pkg/query no longer marks", slug)
	}
}

// TestGuardedModeConstructsNoResultCache is the behavioural half of the result-cache invariant.
// TestQueryGoRetainsNewConstructorHooks pins the discardCacheIfDisabled call site textually, which
// catches a merge that DELETES query.go's hook -- but not a discardCacheIfDisabled that is changed
// to return cache unconditionally, and not a resolution of the form `_ = discardCacheIfDisabled(...)`
// that keeps the pinned substring and drops the assignment. Both of those leave a live otter cache
// on a guarded DB, which is exactly what executeGuarded's validate-before-cache-read ordering
// assumes cannot happen. Asserting on db.cache closes all three loss modes and survives any rename.
func TestGuardedModeConstructsNoResultCache(t *testing.T) {
	db, _ := guardedTransactionDB(t, "CREATE SCHEMA tenant; CREATE TABLE tenant.t AS SELECT 1 AS value;",
		TransactionOptions{Timeout: time.Minute, MaxResultBytes: 1 << 20})

	require.Nil(t, db.cache,
		"guarded mode must hold no otter cache: New constructs one and discardCacheIfDisabled must "+
			"throw it away (FORK[result-cache-discard]). A non-nil cache here means a guarded query "+
			"could be served from cache without the validation and live catalog check that "+
			"executeGuarded runs first.")
}
