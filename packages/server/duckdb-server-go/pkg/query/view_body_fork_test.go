package query

import (
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"
)

// FORK-OWNED TEST FILE. Two-tier validation: admitting a schema-qualified VIEW whose body reads mirror Parquet
// (kata platform#34tp). See view_body.go for why the view admission and the body check are one function.

type mirrorFixture struct {
	db        *DB
	t         *testing.T
	connector *duckdb.Connector
	root      string // the configured --mirror-file-root
	inRoot    string // a Parquet file under root
	outOfRoot string // a Parquet file outside it
}

// privileged runs DDL the way the platform does: on a raw connection, not through *DB. The user path refuses
// exec outright once validation is armed, so every view in these tests is platform-authored by construction --
// which is the assumption the whole boundary rests on (INV-bqsync-no-user-created-views).
func (f mirrorFixture) privileged(statements ...string) {
	f.t.Helper()
	conn, err := f.connector.Connect(f.t.Context())
	require.NoError(f.t, err)
	defer func() { _ = conn.Close() }()
	for _, statement := range statements {
		require.NoError(f.t, execOn(f.t.Context(), conn, statement), statement)
	}
}

// newMirrorFixture builds a guarded DB whose mirror root is set, alongside a Parquet file inside the root and one
// outside it. Both files are real: CREATE VIEW binds eagerly, so a view over a non-existent path cannot even be
// defined, and a test that silently failed to define its view would prove nothing.
func newMirrorFixture(t *testing.T, root string) mirrorFixture {
	t.Helper()
	base := t.TempDir()
	f := mirrorFixture{
		t:         t,
		root:      root,
		inRoot:    filepath.Join(base, "mirror", "a.parquet"),
		outOfRoot: filepath.Join(base, "elsewhere", "secret.parquet"),
	}
	if root == unsetRootSentinel {
		f.root = filepath.Join(base, "mirror")
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(f.inRoot), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(f.outOfRoot), 0o755))
	f.db, f.connector = newGuardedDB(t, f.root)
	f.privileged(
		fmt.Sprintf(`COPY (SELECT 1 AS v) TO %s (FORMAT parquet)`, quoteLiteral(f.inRoot)),
		fmt.Sprintf(`COPY (SELECT 'classified' AS v) TO %s (FORMAT parquet)`, quoteLiteral(f.outOfRoot)),
		`CREATE SCHEMA analytics`,
		`CREATE SCHEMA private_ns`,
	)
	return f
}

// unsetRootSentinel asks newMirrorFixture to derive the root from its own temp dir, which is the usual case. An
// explicit root (including "") is passed through unchanged.
const unsetRootSentinel = "\x00derive"

func newGuardedDB(t *testing.T, root string) (*DB, *duckdb.Connector) {
	t.Helper()
	return transactionTestDB(t,
		WithMaxConnections(1),
		WithResultCacheDisabled(),
		WithFunctionAllowlist(FunctionAllowlistOptions{}),
		WithTransactionalCatalogGuard(TransactionOptions{
			Timeout:        30 * time.Second,
			MaxResultBytes: 8 << 20,
			MirrorFileRoot: root,
		}))
}

// pinnedConn opens the same connection-and-transaction shape executeGuarded runs the catalog check on, so the
// checks under test see a pinned snapshot rather than an ambient one.
func pinnedConn(t *testing.T, db *DB) driver.Conn {
	t.Helper()
	pc, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { db.arrowPool.release(pc) })
	tx, err := pc.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	return pc.conn
}

// checkQuery runs the guarded pair -- authoritative validation, then the catalog check -- in the order
// executeGuarded runs them, and returns the first error either produced.
func checkQuery(t *testing.T, db *DB, conn driver.Conn, statement string, schemas ...string) error {
	t.Helper()
	if len(schemas) == 0 {
		schemas = []string{"analytics"}
	}
	refs, err := db.validateQueryOn(t.Context(), conn, statement, schemas)
	if err != nil {
		return err
	}
	return db.checkCatalogOn(t.Context(), conn, refs, schemas)
}

func TestViewOverAnInRootFileIsServed(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(
		fmt.Sprintf(`CREATE VIEW analytics.mirror AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.inRoot)),
		`CREATE TABLE analytics.physical(v INTEGER)`,
	)

	conn := pinnedConn(t, f.db)

	// CONTROL: a physical table in the same schema, on the same connection in the same run, must still be
	// served. Without it, "the view was served" is indistinguishable from a check that stopped running at all.
	require.NoError(t, checkQuery(t, f.db, conn, `SELECT * FROM analytics.physical`))

	require.NoError(t, checkQuery(t, f.db, conn, `SELECT * FROM analytics.mirror`))
}

func TestViewOverAnOutOfRootFileIsRefused(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.leak AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.outOfRoot)))

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.leak`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "outside the mirror file root")
}

// A root of "/x/mirror" must not admit "/x/mirror-public/...". Found by mutating mirrorFileRoot to return the
// configured value unchanged: every other test in this file still passed, because they only ever place the
// out-of-root file in a sibling DIRECTORY, not under a sibling PREFIX.
func TestSiblingPrefixIsNotUnderTheMirrorRoot(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	sibling := f.root + "-public"
	require.NoError(t, os.MkdirAll(sibling, 0o755))
	decoy := filepath.Join(sibling, "b.parquet")
	f.privileged(
		fmt.Sprintf(`COPY (SELECT 'classified' AS v) TO %s (FORMAT parquet)`, quoteLiteral(decoy)),
		fmt.Sprintf(`CREATE VIEW analytics.sibling AS SELECT * FROM read_parquet(%s)`, quoteLiteral(decoy)),
	)

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.sibling`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "outside the mirror file root")
}

func TestViewIsRefusedWhenNoMirrorRootIsConfigured(t *testing.T) {
	f := newMirrorFixture(t, "")
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.mirror AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.inRoot)))

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.mirror`)
	require.ErrorIs(t, err, ErrAccessDenied)
	// The message platform#d5x9 recorded. Unconfigured must be indistinguishable from before this feature.
	require.Contains(t, err.Error(), "'analytics.mirror' is not a physical table")
}

// (c) The body is bound by the CALLER's allowed_schemas, not by what the view's author could reach.
func TestViewBodyCannotReachASchemaTheCallerCannot(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(
		`CREATE TABLE private_ns.salaries(v INTEGER)`,
		`CREATE VIEW analytics.crosser AS SELECT * FROM private_ns.salaries`,
	)

	conn := pinnedConn(t, f.db)

	// CONTROL: the same body IS admitted for a caller who holds private_ns, so the refusal below is about the
	// caller's bound and not about the body being unparseable or the view being broken.
	require.NoError(t, checkQuery(t, f.db, conn, `SELECT * FROM analytics.crosser`, "analytics", "private_ns"))

	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.crosser`, "analytics")
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "unauthorized access to schema 'private_ns'")
}

// (d) The user's own query keeps today's rules: neither syntax may name a file, in-root or not. This is
// invariant 13 restated against a server that now permits file reads SOMEWHERE.
func TestUserQueryStillCannotNameAFile(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(`CREATE TABLE analytics.physical(v INTEGER)`)
	conn := pinnedConn(t, f.db)

	// CONTROL: this connection and token do serve a legitimate query.
	require.NoError(t, checkQuery(t, f.db, conn, `SELECT * FROM analytics.physical`))

	for name, statement := range map[string]string{
		"function form, in root":     fmt.Sprintf(`SELECT * FROM read_parquet(%s)`, quoteLiteral(f.inRoot)),
		"function form, out of root": fmt.Sprintf(`SELECT * FROM read_parquet(%s)`, quoteLiteral(f.outOfRoot)),
		"bare literal, in root":      fmt.Sprintf(`SELECT * FROM %s`, quoteLiteral(f.inRoot)),
		"bare literal, out of root":  fmt.Sprintf(`SELECT * FROM %s`, quoteLiteral(f.outOfRoot)),
		"glob":                       fmt.Sprintf(`SELECT * FROM read_parquet(%s)`, quoteLiteral(filepath.Join(f.root, "*.parquet"))),
		"csv reader":                 fmt.Sprintf(`SELECT * FROM read_csv(%s)`, quoteLiteral(f.inRoot)),
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, checkQuery(t, f.db, conn, statement), ErrAccessDenied)
		})
	}
}

// (e) Recursion into nested views is bounded, and the bound denies rather than truncating the check.
//
// The chain lengths below are LITERALS, not expressions over maxViewDepth. Written the obvious way -- build a
// chain of maxViewDepth+1 and expect a refusal -- the test moves with the constant: raising maxViewDepth to 40
// kept it green, which is a test that asserts the code equals itself. Changing the bound must break this test
// and be a deliberate edit here.
func TestViewRecursionIsBounded(t *testing.T) {
	require.Equal(t, 4, maxViewDepth, "the depth literals below are pinned to this bound")

	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.v0 AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.inRoot)))
	for i := 1; i <= 5; i++ {
		f.privileged(fmt.Sprintf(`CREATE VIEW analytics.v%d AS SELECT * FROM analytics.v%d`, i, i-1))
	}
	conn := pinnedConn(t, f.db)

	// CONTROL: a chain that stays within the bound is served, so the refusal below is the depth check and not
	// nested views failing wholesale. v3 expands v3->v2->v1->v0, four expansions.
	require.NoError(t, checkQuery(t, f.db, conn, `SELECT * FROM analytics.v3`))

	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.v5`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "maximum view nesting depth")
}

// A body may not evade the root check by computing its path. remoteURILiteralValidator scans for constants
// inside an expression and would walk past the concatenation below; the body tier refuses the shape outright.
func TestViewBodyPathMustBeASingleLiteral(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(fmt.Sprintf(`CREATE VIEW analytics.computed AS SELECT * FROM read_parquet(%s || %s)`,
		quoteLiteral(f.root+"/"), quoteLiteral("a.parquet")))

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.computed`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "must be a single constant string literal")
}

func TestViewBodyCannotTraverseOutOfTheRoot(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	// Built by concatenation, not filepath.Join: Join cleans ".." away, and a cleaned path is not what an
	// attacker would write. The literal must reach the validator with its ".." intact.
	traversal := f.root + "/../elsewhere/secret.parquet"
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.traversal AS SELECT * FROM read_parquet(%s)`, quoteLiteral(traversal)))

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.traversal`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "parent-directory segment")
}

// Only the two Parquet readers are added to the body's allowlist. A body reading an in-root file with any other
// reader is refused by the allowlist, before the root check is even reached.
func TestViewBodyMayNotUseANonParquetReader(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	csv := filepath.Join(f.root, "a.csv")
	f.privileged(
		fmt.Sprintf(`COPY (SELECT 1 AS v) TO %s (FORMAT csv)`, quoteLiteral(csv)),
		fmt.Sprintf(`CREATE VIEW analytics.viacsv AS SELECT * FROM read_csv(%s)`, quoteLiteral(csv)),
	)

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.viacsv`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "'read_csv' is not in the allowlist")
}

// A body may not smuggle a bare path literal past the root check as a replacement scan: that parses as a
// BASE_TABLE with an empty schema, which baseTableValidator and cteScopeValidator both refuse in the body set.
func TestViewBodyCannotUseABareFileLiteral(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.bare AS SELECT * FROM %s`, quoteLiteral(f.inRoot)))

	conn := pinnedConn(t, f.db)
	err := checkQuery(t, f.db, conn, `SELECT * FROM analytics.bare`)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Contains(t, err.Error(), "with empty schema")
}

func TestViewBodyFromStoredSQL(t *testing.T) {
	for name, tc := range map[string]struct {
		stored string
		want   string
		refuse bool
	}{
		"plain":            {stored: `CREATE VIEW s.v AS SELECT 1;`, want: `SELECT 1;`},
		"column alias":     {stored: `CREATE VIEW s.v (a, b) AS SELECT 1, 2;`, want: `SELECT 1, 2;`},
		"as inside name":   {stored: `CREATE VIEW s."odd AS name" AS SELECT 1;`, want: `SELECT 1;`},
		"as inside body":   {stored: `CREATE VIEW s.v AS SELECT x AS "y AS z" FROM t;`, want: `SELECT x AS "y AS z" FROM t;`},
		"as inside string": {stored: `CREATE VIEW s.v AS SELECT 'a AS b' AS c;`, want: `SELECT 'a AS b' AS c;`},
		"lowercase":        {stored: `create view s.v as select 1;`, want: `select 1;`},
		"doubled quote":    {stored: `CREATE VIEW s."he""AS""re" AS SELECT 1;`, want: `SELECT 1;`},
		"not a view":       {stored: `CREATE TABLE s.v(a INTEGER);`, refuse: true},
		"no top-level as":  {stored: `CREATE VIEW s.v;`, refuse: true},
		"empty body":       {stored: `CREATE VIEW s.v AS `, refuse: true},
		"unterminated":     {stored: `CREATE VIEW s."v AS SELECT 1;`, refuse: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := viewBodyFromStoredSQL(tc.stored)
			if tc.refuse {
				require.ErrorIs(t, err, ErrAccessDenied)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// The whole path, through the coordinator rather than through its parts: executeGuarded must serve the view and
// commit before any byte is returned.
func TestGuardedExecutionServesAMirrorView(t *testing.T) {
	f := newMirrorFixture(t, unsetRootSentinel)
	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.mirror AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.inRoot)))

	data, err := f.db.executeGuarded(t.Context(), `SELECT v FROM analytics.mirror`, []string{"analytics"}, responseJSON)
	require.NoError(t, err)
	require.JSONEq(t, `[{"v":1}]`, string(data))

	f.privileged(fmt.Sprintf(
		`CREATE VIEW analytics.leak AS SELECT * FROM read_parquet(%s)`, quoteLiteral(f.outOfRoot)))
	_, err = f.db.executeGuarded(t.Context(), `SELECT v FROM analytics.leak`, []string{"analytics"}, responseJSON)
	require.ErrorIs(t, err, ErrAccessDenied)
}

func TestMirrorFileRootRequiresAFunctionAllowlist(t *testing.T) {
	connector, err := duckdb.NewConnector(filepath.Join(t.TempDir(), "test.duckdb"), nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, connector.Close()) }()
	_, err = New(t.Context(), connector,
		WithResultCacheDisabled(),
		WithTransactionalCatalogGuard(TransactionOptions{
			Timeout:        30 * time.Second,
			MaxResultBytes: 8 << 20,
			MirrorFileRoot: "/tmp/mirror",
		}))
	require.ErrorContains(t, err, "mirror file root requires a configured function allowlist")
}
