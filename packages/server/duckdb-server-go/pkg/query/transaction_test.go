package query

import (
	"context"
	"database/sql/driver"
	"path/filepath"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"
)

func transactionTestDB(t *testing.T, opts ...OptionFunc) (*DB, *duckdb.Connector) {
	t.Helper()
	connector, err := duckdb.NewConnector(filepath.Join(t.TempDir(), "test.duckdb"), nil)
	require.NoError(t, err)
	db, err := New(t.Context(), connector, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); require.NoError(t, connector.Close()) })
	return db, connector
}

func TestPooledArrowCarriesTheSameDriverConnection(t *testing.T) {
	db, _ := transactionTestDB(t, WithMaxConnections(1))
	pc, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(pc)

	tx, err := pc.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback()
	require.NoError(t, execOn(t.Context(), pc.conn,
		`CREATE TEMP TABLE same_conn_probe AS SELECT 'marker' AS value`))

	rdr, err := pc.arrow.QueryContext(t.Context(), `SELECT value FROM same_conn_probe`)
	require.NoError(t, err)
	defer rdr.Release()
	require.True(t, rdr.Next())
	got := string(append([]byte(nil), rdr.RecordBatch().Column(0).ValueStr(0)...))
	require.Equal(t, "marker", got)
}

// guardedTransactionDB seeds seedSQL into a fresh file-backed database and returns a guarded DB opened against the
// same file. Seeding uses its own *duckdb.Connector, separate from the one the returned DB and connector use:
// (*sql.DB).Close cascades to closing the driver.Connector it wraps (database/sql calls
// db.connector.(io.Closer).Close if the connector implements it, and *duckdb.Connector does), which permanently
// tears down that connector's underlying native DuckDB handle. Sharing one connector between the seed DB and the
// guarded DB would mean seed.Close() (needed because Exec is unreachable once db.transaction != nil) kills the
// connector the guarded DB depends on, so every subsequent query fails with "could not connect to database".
// Opening a second, independent connector against the same on-disk file after the first is fully closed avoids
// that: DuckDB's file lock is released when the seed connector closes, so the second connector opens cleanly.
func guardedTransactionDB(t *testing.T, seedSQL string, options TransactionOptions) (*DB, *duckdb.Connector) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guarded.duckdb")
	if seedSQL != "" {
		seedConnector, err := duckdb.NewConnector(path, nil)
		require.NoError(t, err)
		seed, err := New(t.Context(), seedConnector)
		require.NoError(t, err)
		require.NoError(t, seed.Exec(t.Context(), seedSQL))
		seed.Close()
		require.NoError(t, seedConnector.Close())
	}
	connector, err := duckdb.NewConnector(path, nil)
	require.NoError(t, err)
	db, err := New(t.Context(), connector,
		WithMaxConnections(1),
		WithResultCacheDisabled(),
		WithTransactionalCatalogGuard(options),
	)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); require.NoError(t, connector.Close()) })
	return db, connector
}

// TestExecuteGuardedRejectsEmptySchemaList covers I3: newValidators (query.go) only installs the
// base-table validator when len(allowedSchemas) > 0, so an empty schemas slice would otherwise
// leave only the function allowlist, URI-literal rejection, and the catalog's physical-table check
// active on the path through executeGuarded -- none of which asks "is this schema authorized?".
// Without the guard at the top of executeGuarded, this query would succeed and return
// "other-tenant-secret", exactly as described in the finding: "SELECT * FROM other_tenant.secret
// would pass." This is exercised directly at the query.DB level (not through pkg/server) because
// the point of the fix is that this package's own guarantee must not depend on a caller elsewhere
// (schema resolution, JWT claim validation, header parsing) doing the right thing first.
func TestExecuteGuardedRejectsEmptySchemaList(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA other_tenant; CREATE TABLE other_tenant.secret(value VARCHAR); INSERT INTO other_tenant.secret VALUES ('other-tenant-secret')`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

	data, _, err := db.QueryJSON(t.Context(), `SELECT * FROM other_tenant.secret`, []string{}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.NotContains(t, string(data), "other-tenant-secret")

	arrowData, _, err := db.QueryArrow(t.Context(), `SELECT * FROM other_tenant.secret`, []string{}, false)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Empty(t, arrowData)
}

func TestGuardedQueryReusesPoolSizeOne(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: 500 * time.Millisecond, MaxResultBytes: 1 << 20})
	for i := 0; i < 2; i++ {
		data, hit, err := db.QueryJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, true)
		require.NoError(t, err)
		require.False(t, hit)
		require.Contains(t, string(data), "1")
	}
}

func TestGuardedQueryRollsBackAfterExecutionError(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	_, _, err := db.QueryJSON(t.Context(), `SELECT CAST('not-an-integer' AS INTEGER)`, []string{"tenant_a"}, false)
	require.Error(t, err)
	data, _, err := db.QueryJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, false)
	require.NoError(t, err)
	require.Contains(t, string(data), "1")
}

func TestGuardedQueryTimeoutDiscardsConnection(t *testing.T) {
	// NOTE: the timeout here is 200ms, not the 20ms in the brief, specifically to give the recovery query below
	// headroom over checkCatalogOn's live duckdb_functions() scan, independently measured at ~10-19ms per guarded
	// query on this machine. At 20ms that cost alone intermittently blew the deadline on the second, unrelated
	// sanity-check query (~40% failure rate across repeated -count=10 runs), even though nothing was hung, raced,
	// or nested-acquired: every failure was a clean, fast ErrQueryTimeout. 200ms preserves the test's intent
	// (proving a guard-deadline interrupt discards the connection and the DB recovers) since the runaway
	// range(1000000000) cross join still vastly exceeds it; it only removes margin-induced flakiness unrelated to
	// what this test verifies.
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: 200 * time.Millisecond, MaxResultBytes: 1 << 20})
	_, _, err := db.QueryJSON(t.Context(),
		`SELECT sum(i) FROM range(1000000000) t(i) CROSS JOIN tenant_a.metrics`, []string{"tenant_a"}, false)
	require.ErrorIs(t, err, ErrQueryTimeout)
	data, _, err := db.QueryJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, false)
	require.NoError(t, err)
	require.Contains(t, string(data), "1")
}

func TestGuardedQueryCancellationDiscardsConnection(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: 500 * time.Millisecond, MaxResultBytes: 1 << 20})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := db.QueryJSON(ctx,
			`SELECT sum(i) FROM range(1000000000) t(i) CROSS JOIN tenant_a.metrics`, []string{"tenant_a"}, false)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	var canceledErr error
	select {
	case canceledErr = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled query did not return")
	}
	require.ErrorIs(t, canceledErr, context.Canceled)
	data, _, err := db.QueryJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, false)
	require.NoError(t, err)
	require.Contains(t, string(data), "1")
}

func TestGuardedQueryRejectsOversizedJSON(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v VARCHAR); INSERT INTO tenant_a.metrics VALUES ('long-value')`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 4})
	_, _, err := db.QueryJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, false)
	require.ErrorIs(t, err, ErrResultTooLarge)
}

func TestGuardedQueryRejectsOversizedArrow(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v VARCHAR); INSERT INTO tenant_a.metrics VALUES ('long-value')`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 4})
	_, _, err := db.QueryArrow(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, false)
	require.ErrorIs(t, err, ErrResultTooLarge)
}

func TestDisabledResultCacheIgnoresPersist(t *testing.T) {
	db, connector := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	const statement = `SELECT * FROM tenant_a.metrics`
	first, hit, err := db.QueryJSON(t.Context(), statement, []string{"tenant_a"}, true)
	require.NoError(t, err)
	require.False(t, hit)
	require.Contains(t, string(first), "1")
	writer, err := connector.Connect(t.Context())
	require.NoError(t, err)
	require.NoError(t, execOn(t.Context(), writer, `UPDATE tenant_a.metrics SET v = 2`))
	require.NoError(t, writer.Close())
	second, hit, err := db.QueryJSON(t.Context(), statement, []string{"tenant_a"}, true)
	require.NoError(t, err)
	require.False(t, hit)
	require.Contains(t, string(second), "2")
}

type checkpointWriter struct {
	connector *duckdb.Connector
	called    bool
}

func (w *checkpointWriter) Write(p []byte) (int, error) {
	w.called = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := w.connector.Connect(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := execOn(ctx, conn, `CHECKPOINT`); err != nil {
		return 0, err
	}
	return len(p), nil
}

func TestWriteJSONWritesOnlyAfterCommit(t *testing.T) {
	db, connector := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	writer := &checkpointWriter{connector: connector}
	require.NoError(t, db.WriteJSON(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, writer))
	require.True(t, writer.called)
}

func TestWriteArrowWritesOnlyAfterCommit(t *testing.T) {
	db, connector := guardedTransactionDB(t,
		`CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER); INSERT INTO tenant_a.metrics VALUES (1)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})
	writer := &checkpointWriter{connector: connector}
	require.NoError(t, db.WriteArrow(t.Context(), `SELECT * FROM tenant_a.metrics`, []string{"tenant_a"}, writer))
	require.True(t, writer.called)
}
