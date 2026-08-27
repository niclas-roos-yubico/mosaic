package query

import (
	"bytes"
	"context"
	"io"
	"os"
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
