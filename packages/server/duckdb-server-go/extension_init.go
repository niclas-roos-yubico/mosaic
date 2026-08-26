package main

import (
	"context"
	"database/sql/driver"
	"strings"
	"sync"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/extensions"
)

type extensionInitializer struct {
	ctx        context.Context
	raw        string
	names      []string
	mu         sync.Mutex
	installed  bool
	installErr error
}

// newExtensionInitializer retains ctx in the returned closure, which fires on every future
// physical connection -- including ones opened long after startup, e.g. during pool growth or a
// later graceful-shutdown drain. context.WithoutCancel detaches it from the caller's
// cancellation/deadline so a shutdown signal on the original ctx cannot fail a new connection's
// INSTALL/LOAD sequence, which (*duckdb.Connector).Connect would otherwise close and reject
// silently.
func newExtensionInitializer(ctx context.Context, raw string) func(driver.ExecerContext) error {
	init := &extensionInitializer{ctx: context.WithoutCancel(ctx), raw: raw, names: extensionNames(raw)}
	return init.initialize
}

func extensionNames(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "|")
		names = append(names, strings.TrimSpace(name))
	}
	return names
}

func (i *extensionInitializer) initialize(execer driver.ExecerContext) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.installed {
		i.installErr = extensions.ParseAndInstall(i.ctx, execer, i.raw)
		i.installed = i.installErr == nil
		return i.installErr
	}
	for _, name := range i.names {
		if err := extensions.LoadInstalled(i.ctx, execer, name); err != nil {
			return err
		}
	}
	return nil
}
