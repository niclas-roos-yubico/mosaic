package query

import (
	"database/sql/driver"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogCheckAllowsOnlyPhysicalTables(t *testing.T) {
	db, _ := transactionTestDB(t, WithMaxConnections(1))
	require.NoError(t, db.Exec(t.Context(), `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.metrics(v INTEGER)`))
	pc, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(pc)
	tx, err := pc.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, checkCatalogOn(t.Context(), pc.conn, []tableRef{{SchemaName: "tenant_a", TableName: "metrics"}}))
}

func TestCatalogCheckRejectsViewAndUserMacro(t *testing.T) {
	for name, ddl := range map[string]string{
		"view":  `CREATE SCHEMA tenant_a; CREATE VIEW tenant_a.target AS SELECT 1 AS v`,
		"macro": `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.target(v INTEGER); CREATE MACRO tenant_a.range(n) AS TABLE SELECT n AS v`,
	} {
		t.Run(name, func(t *testing.T) {
			db, _ := transactionTestDB(t, WithMaxConnections(1))
			require.NoError(t, db.Exec(t.Context(), ddl))
			pc, err := db.arrowPool.acquire(t.Context())
			require.NoError(t, err)
			defer db.arrowPool.release(pc)
			tx, err := pc.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			err = checkCatalogOn(t.Context(), pc.conn, []tableRef{{SchemaName: "tenant_a", TableName: "target"}})
			require.ErrorIs(t, err, ErrAccessDenied)
		})
	}
}

func TestCatalogTransactionPinsTableBeforeViewReplacement(t *testing.T) {
	db, connector := transactionTestDB(t, WithMaxConnections(1))
	require.NoError(t, db.Exec(t.Context(), `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.target(v VARCHAR); INSERT INTO tenant_a.target VALUES ('safe')`))
	reader, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	readerReleased := false
	defer func() {
		if !readerReleased {
			db.arrowPool.release(reader)
		}
	}()
	tx, err := reader.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	txFinished := false
	defer func() {
		if !txFinished {
			_ = tx.Rollback()
		}
	}()
	refs, err := db.validateQueryOn(t.Context(), reader.conn, `SELECT * FROM tenant_a.target`, []string{"tenant_a"})
	require.NoError(t, err)
	require.NoError(t, checkCatalogOn(t.Context(), reader.conn, refs))

	writer, err := connector.Connect(t.Context())
	require.NoError(t, err)
	defer func() { _ = writer.Close() }()
	wtx, err := writer.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, execOn(t.Context(), writer, `DROP TABLE tenant_a.target; CREATE VIEW tenant_a.target AS SELECT 'canary' AS v`))
	require.NoError(t, wtx.Commit())

	rdr, err := reader.arrow.QueryContext(t.Context(), `SELECT * FROM tenant_a.target`)
	require.NoError(t, err)
	require.True(t, rdr.Next())
	got := string(append([]byte(nil), rdr.RecordBatch().Column(0).ValueStr(0)...))
	rdr.Release()
	require.Equal(t, "safe", got)
	require.NoError(t, tx.Commit())
	txFinished = true
	db.arrowPool.release(reader)
	readerReleased = true

	next, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(next)
	nextTx, err := next.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = nextTx.Rollback() }()
	nextRefs, err := db.validateQueryOn(t.Context(), next.conn, `SELECT * FROM tenant_a.target`, []string{"tenant_a"})
	require.NoError(t, err)
	require.ErrorIs(t, checkCatalogOn(t.Context(), next.conn, nextRefs), ErrAccessDenied)
}

func TestCatalogTransactionPinsMacroFreeSnapshot(t *testing.T) {
	db, connector := transactionTestDB(t, WithMaxConnections(1))
	require.NoError(t, db.Exec(t.Context(), `CREATE SCHEMA tenant_a`))
	const statement = `SELECT * FROM tenant_a.range(3)`
	reader, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	readerReleased := false
	defer func() {
		if !readerReleased {
			db.arrowPool.release(reader)
		}
	}()
	tx, err := reader.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	txFinished := false
	defer func() {
		if !txFinished {
			_ = tx.Rollback()
		}
	}()
	refs, err := db.validateQueryOn(t.Context(), reader.conn, statement, []string{"tenant_a"})
	require.NoError(t, err)
	require.NoError(t, checkCatalogOn(t.Context(), reader.conn, refs))

	writer, err := connector.Connect(t.Context())
	require.NoError(t, err)
	defer func() { _ = writer.Close() }()
	wtx, err := writer.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, execOn(t.Context(), writer, `CREATE MACRO tenant_a.range(n) AS TABLE SELECT 'canary' AS v`))
	require.NoError(t, wtx.Commit())

	_, err = reader.arrow.QueryContext(t.Context(), statement)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "canary")
	require.NoError(t, tx.Rollback())
	txFinished = true
	db.arrowPool.release(reader)
	readerReleased = true

	next, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(next)
	nextTx, err := next.conn.(driver.ConnBeginTx).BeginTx(t.Context(), driver.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = nextTx.Rollback() }()
	nextRefs, err := db.validateQueryOn(t.Context(), next.conn, statement, []string{"tenant_a"})
	require.NoError(t, err)
	require.ErrorIs(t, checkCatalogOn(t.Context(), next.conn, nextRefs), ErrAccessDenied)
}
