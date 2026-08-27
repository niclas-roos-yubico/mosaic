package main

import (
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"testing"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"
)

// bakedArtifacts locates real signed extension builds so this test exercises the actual LOAD path
// rather than a fake execer. It skips rather than fails when they are absent: CI runners have no
// extension directory, and a skip is honest where a fabricated pass would not be.
//
// Deliberately reads DuckDB's own extension directory instead of downloading anything -- the whole
// point of --load-extension-file is that the deployed pod has no network.
func bakedArtifacts(t *testing.T) (httpfs, quack string) {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	matches, err := filepath.Glob(filepath.Join(home, ".duckdb", "extensions", "v*", "*", "quack.duckdb_extension"))
	require.NoError(t, err)
	if len(matches) == 0 {
		t.Skip("no locally installed quack.duckdb_extension; skipping real-load test")
	}
	dir := filepath.Dir(matches[0])
	httpfs = filepath.Join(dir, "httpfs.duckdb_extension")
	if _, err := os.Stat(httpfs); err != nil {
		t.Skip("no locally installed httpfs.duckdb_extension; skipping real-load test")
	}
	return httpfs, matches[0]
}

// The end-to-end claim F1 exists to establish: a signed artifact loads from an absolute path, with
// allow_unsigned_extensions at its default of false, through the connector initializer the binary
// actually installs -- on every connection, including ones opened later.
func TestBakedExtensionsLoadByAbsolutePath(t *testing.T) {
	httpfs, quack := bakedArtifacts(t)

	// httpfs first: quack depends on it, and a wrong order is a real deployment mistake.
	files := []string{httpfs, quack}
	require.NoError(t, validateExtensionFiles(files))

	init := newExtensionInitializer(t.Context(), "", files)
	connector, err := duckdb.NewConnector(":memory:", func(execer driver.ExecerContext) error {
		return init(execer)
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connector.Close()) })

	db := sql.OpenDB(connector)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	var unsigned string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT current_setting('allow_unsigned_extensions')`).Scan(&unsigned))
	require.Equal(t, "false", unsigned, "signed-extension mode must be the thing under test")

	for _, name := range []string{"httpfs", "quack"} {
		var loaded bool
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT loaded FROM duckdb_extensions() WHERE extension_name = ?`, name).Scan(&loaded))
		require.True(t, loaded, "%s must be loaded from its absolute path", name)
	}

	// A second physical connection must load them too -- pool growth after startup is the case that
	// would otherwise serve queries from a connection where quack was never loaded.
	require.NoError(t, db.PingContext(t.Context()))
	var quackLoaded bool
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT loaded FROM duckdb_extensions() WHERE extension_name = 'quack'`).Scan(&quackLoaded))
	require.True(t, quackLoaded)
}

// A tampered artifact must be refused by DuckDB's signature check, offline. This is what lets the
// deployment rely on baked files without allow_unsigned_extensions.
func TestCorruptedArtifactIsRejected(t *testing.T) {
	_, quack := bakedArtifacts(t)

	payload, err := os.ReadFile(quack)
	require.NoError(t, err)
	require.Greater(t, len(payload), 1024)
	payload[len(payload)/2] ^= 0xff

	corrupted := filepath.Join(t.TempDir(), "quack.duckdb_extension")
	require.NoError(t, os.WriteFile(corrupted, payload, 0o600))

	init := newExtensionInitializer(t.Context(), "", []string{corrupted})
	connector, err := duckdb.NewConnector(":memory:", func(execer driver.ExecerContext) error {
		return init(execer)
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = connector.Close() })

	_, err = connector.Connect(t.Context())
	require.Error(t, err, "a corrupted artifact must not load")
	require.ErrorContains(t, err, "load extension file")
}
