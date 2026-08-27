package main

// FORK-OWNED FILE. The repeatable --load-extension-file flag: its flag.Value type, its startup
// validation, and the per-connection LOAD it drives. None of this is upstream's concern -- upstream
// installs extensions by name from a repository, which a read-only, egress-restricted pod cannot do.
//
// Why a separate mechanism rather than extending --load-extensions: that flag's initializer runs
// `INSTALL <name>` against a DuckDB repository on the first physical connection. In the deployed
// image there is no network and no writable extension directory, so the only usable path is
// `LOAD '<absolute path>'` against an artifact baked into the image. pkg/extensions.LoadFile already
// does exactly that and had no caller; this file is the caller.

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/extensions"
)

const extensionFileSuffix = ".duckdb_extension"

// extensionFileFlag collects --load-extension-file occurrences in the order given. Order is
// preserved because it is load order, and an extension whose dependency has not been loaded yet
// fails: quack requires httpfs, so httpfs must be listed first.
type extensionFileFlag struct {
	values []string
}

func (f *extensionFileFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("path must not be empty")
	}
	f.values = append(f.values, value)
	return nil
}

func (f *extensionFileFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.values, ",")
}

// paths is nil-safe so a platformConfig built without registerPlatformFlags -- every test that
// constructs one directly -- reads as "no baked artifacts" rather than panicking in validate.
func (f *extensionFileFlag) paths() []string {
	if f == nil {
		return nil
	}
	return f.values
}

// validateExtensionFiles rejects anything that would only fail later, on a connection, where the
// error surfaces as a confusing pool failure rather than a startup refusal. It runs in
// platformConfig.validate, before any resource is allocated.
//
// Absolute paths only: a relative path resolves against the process working directory, which is not
// a property the deployment controls as tightly as the image layout, and DuckDB derives the
// extension's initialization symbol from the basename either way.
func validateExtensionFiles(paths []string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("--load-extension-file must be an absolute path: %q", path)
		}
		if filepath.Ext(path) != extensionFileSuffix {
			return fmt.Errorf("--load-extension-file must name a %s artifact: %q", extensionFileSuffix, path)
		}
		if _, ok := seen[path]; ok {
			return fmt.Errorf("--load-extension-file repeated: %q", path)
		}
		seen[path] = struct{}{}

		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("--load-extension-file is not readable: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("--load-extension-file is a directory: %q", path)
		}
	}
	return nil
}

// loadExtensionFiles issues one LOAD per baked artifact, in flag order, on the connection being
// initialized. It runs on EVERY physical connection, not once: DuckDB's loaded-extension set is
// per-connection, which is the same reason upstream's extensionInitializer re-LOADs on connections
// after the first.
//
// Signature verification happens inside DuckDB and is offline -- a corrupted artifact is rejected
// with `signature is either missing or invalid` even with no network -- so allow_unsigned_extensions
// stays at its default of false and is never set here.
func loadExtensionFiles(ctx context.Context, execer driver.ExecerContext, paths []string) error {
	for _, path := range paths {
		if err := extensions.LoadFile(ctx, execer, path); err != nil {
			return fmt.Errorf("load extension file %q: %w", path, err)
		}
	}
	return nil
}
