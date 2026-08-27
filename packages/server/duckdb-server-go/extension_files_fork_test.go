package main

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeArtifact(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("not a real extension"), 0o600))
	return path
}

func TestExtensionFileFlagCollectsInOrder(t *testing.T) {
	f := &extensionFileFlag{}
	require.NoError(t, f.Set("/opt/ext/httpfs.duckdb_extension"))
	require.NoError(t, f.Set("  /opt/ext/quack.duckdb_extension  "))
	// Order is load order: httpfs must precede quack, so the flag must not sort or dedupe silently.
	require.Equal(t, []string{"/opt/ext/httpfs.duckdb_extension", "/opt/ext/quack.duckdb_extension"}, f.values)
	require.Equal(t, "/opt/ext/httpfs.duckdb_extension,/opt/ext/quack.duckdb_extension", f.String())
}

func TestExtensionFileFlagRejectsEmpty(t *testing.T) {
	f := &extensionFileFlag{}
	require.Error(t, f.Set("   "))
	require.Empty(t, f.values)
}

func TestValidateExtensionFiles(t *testing.T) {
	dir := t.TempDir()
	good := writeArtifact(t, dir, "quack.duckdb_extension")
	wrongExt := writeArtifact(t, dir, "quack.so")
	subdir := filepath.Join(dir, "nested.duckdb_extension")
	require.NoError(t, os.Mkdir(subdir, 0o755))

	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{"none", nil, ""},
		{"valid", []string{good}, ""},
		{"relative", []string{"ext/quack.duckdb_extension"}, "must be an absolute path"},
		{"wrong suffix", []string{wrongExt}, "must name a .duckdb_extension artifact"},
		{"repeated", []string{good, good}, "repeated"},
		{"missing", []string{filepath.Join(dir, "absent.duckdb_extension")}, "is not readable"},
		{"directory", []string{subdir}, "is a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExtensionFiles(tt.paths)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.want)
		})
	}
}

// The initializer must LOAD the baked artifacts on EVERY connection, not just the first: DuckDB's
// loaded-extension set is per-connection, so a pool that grows after startup would otherwise serve
// queries from a connection where quack was never loaded.
func TestExtensionInitializerLoadsFilesOnEveryConnection(t *testing.T) {
	rec := &recordingExecer{}
	init := newExtensionInitializer(t.Context(), "", []string{"/opt/ext/httpfs.duckdb_extension", "/opt/ext/quack.duckdb_extension"})

	require.NoError(t, init(rec))
	require.NoError(t, init(rec))

	require.Equal(t, []string{
		`LOAD '/opt/ext/httpfs.duckdb_extension'`,
		`LOAD '/opt/ext/quack.duckdb_extension'`,
		`LOAD '/opt/ext/httpfs.duckdb_extension'`,
		`LOAD '/opt/ext/quack.duckdb_extension'`,
	}, rec.snapshot())
}

// failingExecer fails the first statement it is given, so a test can prove initialization aborts
// rather than continuing to the repository install path.
type failingExecer struct{ statements []string }

func (f *failingExecer) ExecContext(_ context.Context, statement string, _ []driver.NamedValue) (driver.Result, error) {
	f.statements = append(f.statements, statement)
	return nil, errors.New("signature is either missing or invalid")
}

// A baked-file failure must abort connection initialization rather than fall through to the
// repository install path, which would leave a connection live without quack loaded.
func TestExtensionInitializerStopsOnFileFailure(t *testing.T) {
	rec := &failingExecer{}
	init := newExtensionInitializer(t.Context(), "json", []string{"/opt/ext/broken.duckdb_extension"})

	err := init(rec)
	require.ErrorContains(t, err, "load extension file")
	require.Len(t, rec.statements, 1, "must not continue to the repository install after a file failure")
}
