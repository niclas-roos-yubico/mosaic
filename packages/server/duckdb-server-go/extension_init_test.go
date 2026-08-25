package main

import (
	"context"
	"database/sql/driver"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingExecer struct {
	mu         sync.Mutex
	statements []string
}

func (f *recordingExecer) ExecContext(_ context.Context, statement string, _ []driver.NamedValue) (driver.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statements = append(f.statements, statement)
	return driver.RowsAffected(0), nil
}

func (f *recordingExecer) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.statements...)
}

func TestExtensionInitializerInstallsOnceThenLoads(t *testing.T) {
	init := newExtensionInitializer(t.Context(), "json,httpfs,quack")
	fake := &recordingExecer{}
	require.NoError(t, init(fake))
	require.Equal(t, []string{
		"INSTALL 'json'", "LOAD 'json'",
		"INSTALL 'httpfs'", "LOAD 'httpfs'",
		"INSTALL 'quack'", "LOAD 'quack'",
	}, fake.snapshot())
	require.NoError(t, init(fake))
	require.Equal(t, []string{
		"INSTALL 'json'", "LOAD 'json'",
		"INSTALL 'httpfs'", "LOAD 'httpfs'",
		"INSTALL 'quack'", "LOAD 'quack'",
		"LOAD 'json'", "LOAD 'httpfs'", "LOAD 'quack'",
	}, fake.snapshot())
}

func TestExtensionInitializerConcurrentCallsStillInstallOnce(t *testing.T) {
	init := newExtensionInitializer(t.Context(), "json,httpfs,quack")
	fake := &recordingExecer{}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- init(fake) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	installs := 0
	for _, statement := range fake.snapshot() {
		if strings.HasPrefix(statement, "INSTALL ") {
			installs++
		}
	}
	require.Equal(t, 3, installs)
}
