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

func newExtensionInitializer(ctx context.Context, raw string) func(driver.ExecerContext) error {
	init := &extensionInitializer{ctx: ctx, raw: raw, names: extensionNames(raw)}
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
