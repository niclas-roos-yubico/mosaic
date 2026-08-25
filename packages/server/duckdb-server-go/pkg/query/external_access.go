package query

import (
	"context"
	"fmt"
)

func (db *DB) DisableExternalAccess(ctx context.Context) error {
	if _, err := db.db.ExecContext(ctx, `SET enable_external_access = false`); err != nil {
		return fmt.Errorf("query: disable external access: %w", err)
	}
	return nil
}

func (db *DB) ExternalAccessEnabled(ctx context.Context) (bool, error) {
	var enabled bool
	if err := db.db.QueryRowContext(ctx,
		`SELECT value::BOOLEAN FROM duckdb_settings() WHERE name = 'enable_external_access'`).Scan(&enabled); err != nil {
		return false, fmt.Errorf("query: read external access setting: %w", err)
	}
	return enabled, nil
}
