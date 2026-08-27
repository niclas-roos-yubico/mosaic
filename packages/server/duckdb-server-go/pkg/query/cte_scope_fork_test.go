package query

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// FORK-OWNED FILE. Regression suite for kata platform#8k4b: an unreferenced CTE named after the target
// defeated the empty-schema base-table exemption in baseTableValidator, which bought reads of tables outside
// allowed_schemas and -- with external access on -- arbitrary local file reads.
//
// Every negative case below is a query that returned rows on fork/main e7479720. Every positive case is
// ordinary CTE usage that must keep working: this file is as much a guard against over-tightening the
// exemption as against re-opening it, because the fix runs on every validated query in the data plane.
//
// The scoping rules asserted here were measured against DuckDB, not inferred from the grammar. Where a case
// exists only because DuckDB resolves it in a way the AST shape does not suggest, the measurement is in the
// comment next to it.

// ---------------------------------------------------------------------------
// The bypass, end to end, through the ordinary browser query path.
// ---------------------------------------------------------------------------

// TestUnreferencedCTEDoesNotExposeATableOutsideAllowedSchemas is the reproduction from platform#8k4b, reduced
// to the one boundary that holds in the current external-access-off deployment: allowed_schemas. It asserts on
// the observable outcome -- whether the canary row reaches the caller -- not on which validator objected.
func TestUnreferencedCTEDoesNotExposeATableOutsideAllowedSchemas(t *testing.T) {
	db := setupTestDB(t)
	require.NoError(t, db.Exec(t.Context(),
		`CREATE SCHEMA analytics;
		 CREATE TABLE analytics.public_data AS SELECT 'PUBLIC' AS v;
		 CREATE TABLE private_data AS SELECT 'CANARY-MAIN-TABLE' AS secret`))

	const attack = `SELECT * FROM (WITH "private_data" AS (SELECT 1) SELECT 1 AS z) a, private_data b`

	out, _, err := db.QueryJSON(t.Context(), attack, []string{"analytics"}, false)
	require.ErrorIs(t, err, ErrAccessDenied,
		"an unreferenced CTE named after the target exempted the target from the empty-schema check")
	require.NotContains(t, string(out), "CANARY-MAIN-TABLE")

	// The control the attack is measured against: the same reference without the decoy CTE was already denied.
	_, _, err = db.QueryJSON(t.Context(), `SELECT * FROM private_data`, []string{"analytics"}, false)
	require.ErrorIs(t, err, ErrAccessDenied)

	// And the allowed schema still works, so the denial above is the CTE decoy being rejected and not the
	// whole validator having been turned into a brick.
	out, _, err = db.QueryJSON(t.Context(), `SELECT * FROM analytics.public_data`, []string{"analytics"}, false)
	require.NoError(t, err)
	require.Contains(t, string(out), "PUBLIC")
}

// TestUnreferencedCTEDoesNotExposeALocalFile covers the other half of platform#8k4b. A bare path in FROM parses
// as a BASE_TABLE whose table_name is the path and whose schema is empty, so the same decoy exempted it. This is
// the half the external-access latch currently mitigates -- the point of the test is that the validator denies it
// on its own, because the BigQuery mirror design has to unlatch external access.
func TestUnreferencedCTEDoesNotExposeALocalFile(t *testing.T) {
	db := setupTestDB(t)
	path := strings.ReplaceAll(t.TempDir()+"/canary.parquet", `'`, `''`)
	require.NoError(t, db.Exec(t.Context(),
		`CREATE SCHEMA analytics; COPY (SELECT 'CANARY-IN-PARQUET' AS secret) TO '`+path+`' (FORMAT PARQUET)`))

	attack := `SELECT * FROM (WITH "` + path + `" AS (SELECT 1) SELECT 1 AS z) a, '` + path + `' b`

	out, _, err := db.QueryJSON(t.Context(), attack, []string{"analytics"}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.NotContains(t, string(out), "CANARY-IN-PARQUET")
}

// TestPrimingStatementCannotExemptALaterStatement covers the cross-statement half of the bug. baseTableValidator
// accumulates cte_map keys into one map that validateParsedAST reuses for every statement in the batch, so
// statement 1 could declare the decoy and statement 2 spend it. Scope is recomputed per statement root here, so
// nothing statement 1 declares survives into statement 2.
func TestPrimingStatementCannotExemptALaterStatement(t *testing.T) {
	db := setupTestDB(t)
	require.NoError(t, db.Exec(t.Context(),
		`CREATE SCHEMA analytics; CREATE TABLE private_data AS SELECT 'CANARY-MAIN-TABLE' AS secret`))

	out, _, err := db.QueryJSON(t.Context(),
		`WITH "private_data" AS (SELECT 1) SELECT 1 AS z; SELECT * FROM private_data;`,
		[]string{"analytics"}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.NotContains(t, string(out), "CANARY-MAIN-TABLE")
}

// ---------------------------------------------------------------------------
// Scope rules, against the production validator set.
// ---------------------------------------------------------------------------

// TestCTEScopeAgainstProductionValidatorSet runs through db.newValidators, not a hand-built validator list, so a
// change that drops the hook from newValidators fails here as well as in the source guard below.
func TestCTEScopeAgainstProductionValidatorSet(t *testing.T) {
	tests := []struct {
		name   string
		sql    string
		denied bool
	}{
		// --- the shapes platform#8k4b enumerated ---
		{
			"inner-scope CTE does not exempt an outer reference",
			`SELECT * FROM (WITH "private_data" AS (SELECT 1) SELECT 1 AS z) a, private_data b`,
			true,
		},
		{
			"CTE in a WHERE scalar subquery does not exempt the outer FROM",
			`SELECT * FROM private_data WHERE 1 = (WITH "private_data" AS (SELECT 1 AS z) SELECT z)`,
			true,
		},
		{
			"CTE in a nested derived table does not exempt a sibling reference",
			`SELECT * FROM (SELECT * FROM (WITH "private_data" AS (SELECT 1) SELECT 1 AS z) i) o, private_data b`,
			true,
		},
		{
			"CTE in a select-list subquery does not exempt the FROM clause",
			`SELECT (WITH "private_data" AS (SELECT 1 AS z) SELECT z) AS x FROM private_data`,
			true,
		},
		// --- ordering inside one WITH. Measured on DuckDB: a CTE is NOT visible to a WITH item declared
		// before it, and NOT visible inside its own body unless the item is RECURSIVE. Both of those
		// references bind to the real table, so scoping that ignored order would leave the hole open.
		{
			"a forward reference in the same WITH binds to the real table, not the CTE",
			`WITH b AS (SELECT * FROM private_data), private_data AS (SELECT 1) SELECT * FROM b`,
			true,
		},
		{
			"a non-recursive CTE does not shadow the real table inside its own body",
			`WITH private_data AS (SELECT * FROM private_data) SELECT * FROM private_data`,
			true,
		},
		// --- ordinary usage that must keep working ---
		{"plain WITH", `WITH x AS (SELECT 1 AS n) SELECT * FROM x`, false},
		{"backward reference in the same WITH", `WITH a AS (SELECT 1 AS n), b AS (SELECT * FROM a) SELECT * FROM b`, false},
		{"outer CTE visible in a derived table", `WITH x AS (SELECT 1 AS n) SELECT * FROM (SELECT * FROM x) s`, false},
		{"outer CTE visible in a scalar subquery", `WITH x AS (SELECT 1 AS n) SELECT (SELECT n FROM x) AS v`, false},
		{"inner CTE shadows an outer one of the same name",
			`WITH x AS (SELECT 1 AS n) SELECT * FROM (WITH x AS (SELECT 2 AS n) SELECT * FROM x) s`, false},
		{"CTE scoped to a derived table, used only there", `SELECT * FROM (WITH x AS (SELECT 1 AS n) SELECT * FROM x) s`, false},
		{"CTE visible across a set operation", `WITH x AS (SELECT 1 AS n) SELECT * FROM x UNION ALL SELECT * FROM x`, false},
		{"recursive CTE references itself", `WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t`, false},
		{"materialized CTE", `WITH x AS MATERIALIZED (SELECT 1 AS n) SELECT * FROM x`, false},
		{"materialized recursive CTE",
			`WITH RECURSIVE t(n) AS MATERIALIZED (SELECT 1 UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t`, false},
		{"qualified reference into an allowed schema is untouched", `SELECT * FROM analytics.metrics`, false},
		{"no FROM clause at all", `SELECT 1 + 2`, false},
	}

	db := setupTestDB(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.ValidateSQL(t.Context(), tt.sql, db.newValidators([]string{"analytics"})...)
			if tt.denied {
				require.ErrorIs(t, err, ErrAccessDenied, "expected a denial for: %s", tt.sql)
				return
			}
			require.NoError(t, err, "over-tightened the CTE exemption for: %s", tt.sql)
		})
	}
}

// TestCTEScopeValidatorFailsClosedWhenTheWalkNeverReachesAStatementRoot pins the one assumption this validator
// makes about upstream's walk: that walkAST enters each statement with an empty keyStack. Scope is a property of
// the path from the root, and the push-based Validator interface cannot express that, so the analysis re-walks
// the statement itself from the root call. If a merge ever changes where the walk starts, CheckNode would stop
// recognising the root and this validator would silently pass everything -- the bypass back, whole suite green.
// Denying instead is what makes that failure loud.
func TestCTEScopeValidatorFailsClosedWhenTheWalkNeverReachesAStatementRoot(t *testing.T) {
	v := newCTEScopeValidator()
	v.CheckNode(map[string]any{"type": "SELECT_NODE"}, []string{"node"})
	require.Len(t, v.Validate(), 1,
		"the analysis never ran and the validator still passed the query; it must fail closed instead")
}

// ---------------------------------------------------------------------------
// Source guard for the hook in query.go, per AGENTS.md's PR checklist.
// ---------------------------------------------------------------------------

// TestNewValidatorsRetainsTheCTEScopeHook. The hook is a single appended statement in an upstream-owned file, so
// a merge resolution can drop it with no conflict, no compile error, and -- because baseTableValidator still
// answers every other question correctly -- almost nothing else going red. Deleting the append is exactly the
// state the bug was found in.
func TestNewValidatorsRetainsTheCTEScopeHook(t *testing.T) {
	body := functionBody(t, readQueryGo(t), "func (db *DB) newValidators(")
	require.True(t, strings.Contains(body, "newCTEScopeValidator("),
		"newValidators no longer appends the scope-aware CTE validator: baseTableValidator's exemption is "+
			"scope-blind on its own and platform#8k4b is re-opened.\n\n"+
			"If upstream restructured newValidators, RE-POINT the append. Never drop it as redundant -- the two "+
			"checks are independent on purpose (AGENTS.md rule 4), and the composite is what holds.")
	require.True(t, strings.Contains(body, "FORK[cte-scope-validator]"),
		"newValidators lost the %q marker; either the hook must come back or its fork-inventory.json row must go",
		"cte-scope-validator")
}

// TestCTEScopeValidatorIsIndependentOfBaseTableValidator asserts the two checks stay separable. AGENTS.md rule 4
// records what happens when someone folds two security gates into one expression to tidy a diff, so this pins
// that baseTableValidator alone still permits the bypass -- i.e. the new validator is carrying the guarantee,
// and merging them would move the guarantee onto the weaker of the two.
func TestCTEScopeValidatorIsIndependentOfBaseTableValidator(t *testing.T) {
	db := setupTestDB(t)
	const attack = `SELECT * FROM (WITH "private_data" AS (SELECT 1) SELECT 1 AS z) a, private_data b`

	require.NoError(t, db.ValidateSQL(t.Context(), attack, newBaseTableValidator([]string{"analytics"})),
		"upstream's baseTableValidator unexpectedly rejects the bypass on its own; if upstream fixed this, "+
			"the fork-owned validator may be retireable -- check before deleting either")
	require.ErrorIs(t, db.ValidateSQL(t.Context(), attack, newCTEScopeValidator()), ErrAccessDenied)
}

// TestCTEScopeValidatorReportsEachTableOnce keeps the denial readable: DuckDB re-emits a materialized WITH item's
// body under both cte_map and the CTE_NODE's own "query" field, so an unguarded walk reports the same reference
// several times.
func TestCTEScopeValidatorReportsEachTableOnce(t *testing.T) {
	db := setupTestDB(t)
	err := db.ValidateSQL(t.Context(),
		`SELECT * FROM private_data a, private_data b, private_data c`, newCTEScopeValidator())
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Equal(t, 1, strings.Count(err.Error(), "private_data"))
}
