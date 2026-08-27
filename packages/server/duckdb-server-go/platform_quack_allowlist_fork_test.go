package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/functionset"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

func boolPtr(v bool) *bool                       { return &v }
func int64Ptr(v int64) *int64                    { return &v }
func intPtr(v int) *int                          { return &v }
func strPtr(v string) *string                    { return &v }
func durationPtr(v time.Duration) *time.Duration { return &v }

// platformDB builds a real DuckDB behind the platform's own query options, so these tests exercise
// the allowlist the deployed binary produces rather than a re-derived name set. Behaviour, not
// inventory: the question is whether a query can call the function, not whether a slice contains it.
func platformDB(t *testing.T, include []string) *query.DB {
	t.Helper()
	connector, err := duckdb.NewConnector(":memory:", nil)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)

	opts := append([]query.OptionFunc{query.WithLogger(logger)}, testPlatformConfig().queryOptions(include)...)
	db, err := query.New(t.Context(), connector, opts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		require.NoError(t, connector.Close())
	})
	return db
}

func denied(t *testing.T, db *query.DB, sql string) error {
	t.Helper()
	_, _, err := db.QueryJSON(t.Context(), sql, []string{"main"}, false)
	return err
}

// kata platform#qt3y: no Quack name may be callable from a user query. quack_query and quack_serve
// were already denied as `elevated`; the compute three -- quack_check_token, quack_nop_authorization,
// quack_uri_parser -- were reaching the default allowlist through coreExtensions.
func TestQuackFunctionsAreNotUserCallable(t *testing.T) {
	db := platformDB(t, nil)

	for _, name := range functionset.Quack.All() {
		err := denied(t, db, "SELECT "+name+"('probe')")
		require.Error(t, err, "Quack function %q must not be user-callable", name)
		require.ErrorContains(t, err, "allowlist", "%q was rejected for the wrong reason", name)
	}
}

// The exclusion must not have collaterally broken ordinary queries.
func TestReviewedDefaultsStillWork(t *testing.T) {
	db := platformDB(t, nil)
	for _, sql := range []string{
		`SELECT sum(x) FROM (SELECT 1 AS x)`,
		`SELECT date_trunc('day', TIMESTAMP '2026-08-27 12:00:00')`,
		`SELECT upper('ok')`,
	} {
		_, _, err := db.QueryJSON(t.Context(), sql, []string{"main"}, false)
		require.NoError(t, err, sql)
	}
}

// Exclude is applied after Include inside the resolver, so an operator cannot re-admit a Quack name
// through --function-allowlist. If that ordering ever inverts, this is what catches it.
func TestOperatorCannotReAddQuackViaAllowlistFlag(t *testing.T) {
	db := platformDB(t, []string{"quack_check_token", "QUACK_QUERY", "  quack_serve  "})

	for _, name := range []string{"quack_check_token", "quack_query", "quack_serve"} {
		require.Error(t, denied(t, db, "SELECT "+name+"('probe')"),
			"--function-allowlist must not be able to re-admit %q", name)
	}
}

// The file-reading functions invariant 13 of the BigQuery mirror design depends on. They are
// `elevated` today; this asserts the deployed behaviour rather than one inventory bucket, because
// with external access on they are the only thing between a session and the private staging Parquet.
func TestFileReadingFunctionsAreNotUserCallable(t *testing.T) {
	db := platformDB(t, nil)
	for _, name := range []string{"read_parquet", "parquet_scan", "read_csv", "read_csv_auto", "read_text", "read_blob", "glob", "sniff_csv", "parquet_schema", "parquet_metadata"} {
		require.Error(t, denied(t, db, "SELECT * FROM "+name+"('/tmp/bqsync/probe.parquet')"),
			"%q would expose the private staging Parquet", name)
	}
}

func TestLoadExtensionFileRequiresExternalAccess(t *testing.T) {
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "quack.duckdb_extension")

	newConfig := func(t *testing.T, externalAccess bool) *platformConfig {
		t.Helper()
		cfg := testPlatformConfig()
		cfg.enableExternalAccess = boolPtr(externalAccess)
		cfg.disableResultCache = boolPtr(true)
		require.NoError(t, cfg.extensionFiles.Set(artifact))
		return cfg
	}

	err := newConfig(t, false).validate("", "")
	require.ErrorContains(t, err, "--load-extension-file requires --enable-external-access=true")

	require.NoError(t, newConfig(t, true).validate("", ""))
}

// A bad path must be refused at startup, not on the first connection that tries to load it.
func TestValidateRejectsBadExtensionPath(t *testing.T) {
	cfg := testPlatformConfig()
	cfg.enableExternalAccess = boolPtr(true)
	cfg.disableResultCache = boolPtr(true)
	require.NoError(t, cfg.extensionFiles.Set("/nonexistent/quack.duckdb_extension"))

	require.ErrorContains(t, cfg.validate("", ""), "is not readable")
}
