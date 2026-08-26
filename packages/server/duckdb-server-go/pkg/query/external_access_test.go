package query_test

import (
	"testing"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

func TestDisableExternalAccessIsOneWay(t *testing.T) {
	connector, err := duckdb.NewConnector(":memory:", nil)
	require.NoError(t, err)
	db, err := query.New(t.Context(), connector)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); require.NoError(t, connector.Close()) })

	enabled, err := db.ExternalAccessEnabled(t.Context())
	require.NoError(t, err)
	require.True(t, enabled)
	require.NoError(t, db.DisableExternalAccess(t.Context()))
	enabled, err = db.ExternalAccessEnabled(t.Context())
	require.NoError(t, err)
	require.False(t, enabled)
	require.Error(t, db.Exec(t.Context(), `SET enable_external_access = true`))
}
