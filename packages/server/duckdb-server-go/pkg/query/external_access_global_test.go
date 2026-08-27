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
//
// It then goes on to open a third connection AFTER the disable, to prove the property production
// actually depends on: every connection the Arrow pool creates lazily for a guarded query comes
// into existence strictly after main.go's one-time latch call, never before it.
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

	// I4: conn1 and conn2 above were both opened BEFORE the disable, so this test so far only proves the property
	// for connections that already existed at latch time. It does not yet prove the property latched mode actually
	// relies on in production: main.go calls DisableExternalAccess once, after the startup extension listing, and then
	// never touches it again -- every connection arrowPool.acquire later hands out for a guarded query is created
	// lazily, on that query's first request, strictly AFTER the latch already dropped. If DuckDB ever re-applied a
	// per-connection default for enable_external_access at connect time (instead of treating it as process-global
	// settings state), a connection opened after the latch would silently come up with external access live again,
	// and nothing above would catch it. A third connection, opened here after the disable, closes that gap.
	conn3, err := db.db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn3.Close() }()

	var afterLatch bool
	require.NoError(t, conn3.QueryRowContext(ctx, enabledQuery).Scan(&afterLatch))
	require.False(t, afterLatch, "a connection opened after the latch dropped must still observe external access disabled")

	_, err = conn3.ExecContext(ctx, `SET enable_external_access = true`)
	require.Error(t, err, "a connection opened after the latch dropped must not be able to re-enable external access either")
}
