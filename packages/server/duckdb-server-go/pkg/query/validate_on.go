package query

// FORK-OWNED FILE. Connection-pinned validation for the guarded coordinator.

import (
	"context"
	"database/sql/driver"
	"fmt"
)

// validateQueryOn runs the same validator set as validateQuery, but on a specific driver.Conn (via validateSQLOn)
// so validation participates in a transaction already open on conn, and additionally collects the base-table
// references the query touched, for the live catalog check.
func (db *DB) validateQueryOn(ctx context.Context, conn driver.Conn, statement string, allowedSchemas []string) ([]tableRef, error) {
	validators := db.newValidators(allowedSchemas)
	collector := newRelationCollector()
	validators = append(validators, collector)
	if err := validateSQLOn(ctx, conn, statement, validators...); err != nil {
		return nil, fmt.Errorf("query: validation failed: %w", err)
	}
	return collector.list(), nil
}
