package query

import (
	"database/sql/driver"
	"path/filepath"
	"testing"

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
