package query

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const discoverTablesQuery = `
	SELECT table_schema, table_name FROM information_schema.tables
	WHERE table_type IN ('BASE TABLE','VIEW') AND table_schema IN ('assets__utilities')
	ORDER BY table_schema, table_name`

func TestGuardedQueryAllowsAuthorizedInformationSchema(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA assets__utilities; CREATE TABLE assets__utilities.date_spine(day DATE)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

	data, _, err := db.QueryJSON(t.Context(), discoverTablesQuery,
		[]string{"assets__utilities", "information_schema"}, false)

	require.NoError(t, err)
	require.Contains(t, string(data), "date_spine")
}

func TestGuardedQueryStillRequiresInformationSchemaGrant(t *testing.T) {
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA assets__utilities; CREATE TABLE assets__utilities.date_spine(day DATE)`,
		TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20})

	_, _, err := db.QueryJSON(t.Context(), discoverTablesQuery,
		[]string{"assets__utilities"}, false)

	require.ErrorIs(t, err, ErrAccessDenied)
}
