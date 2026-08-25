package query

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDisableExternalAccessIsGlobalNotPerConnection guards against an illusion that
// TestDisableExternalAccessIsOneWay (external_access_test.go) cannot rule out on its own:
// database/sql reuses one idle physical connection to serve that test's sequential,
// single-goroutine calls, so it passes identically whether enable_external_access is genuinely a
// global DuckDB setting or merely scoped to whichever connection issued the SET.
//
// This test pins two physical connections open at the same time -- so neither call below can be
// silently served by the same connection as the other -- disables external access through the
// first, and confirms the second, which never itself issues a SET, already observes the change
// and cannot re-enable it either. The two statements below intentionally mirror
// external_access.go's DisableExternalAccess and ExternalAccessEnabled; keep them in sync if
// that file's SQL ever changes.
func TestDisableExternalAccessIsGlobalNotPerConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()

	conn1, err := db.db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn1.Close() }()

	conn2, err := db.db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn2.Close() }()

	// If this ever regresses to 1, the two calls below could be served by the same physical
	// connection and this test would stop distinguishing global scope from per-connection scope
	// -- exactly the illusion it exists to rule out.
	require.GreaterOrEqual(t, db.db.Stats().OpenConnections, 2)

	const enabledQuery = `SELECT value::BOOLEAN FROM duckdb_settings() WHERE name = 'enable_external_access'`

	var before bool
	require.NoError(t, conn2.QueryRowContext(ctx, enabledQuery).Scan(&before))
	require.True(t, before)

	_, err = conn1.ExecContext(ctx, `SET enable_external_access = false`)
	require.NoError(t, err)

	var after bool
	require.NoError(t, conn2.QueryRowContext(ctx, enabledQuery).Scan(&after))
	require.False(t, after, "conn2 never issued SET but must observe conn1's disable if the setting is truly global")

	_, err = conn2.ExecContext(ctx, `SET enable_external_access = true`)
	require.Error(t, err, "the latch must be irreversible from every connection, not just the one that disabled it")
}
