package query

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
)

// execOn runs statement directly on conn, bypassing sql.DB, so that it participates in whatever transaction is
// already open on conn.
func execOn(ctx context.Context, conn driver.Conn, statement string, args ...driver.NamedValue) error {
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		return errors.New("query: DuckDB connection does not implement driver.ExecerContext")
	}
	_, err := execer.ExecContext(ctx, statement, args)
	return err
}

// scalarOn runs statement directly on conn and returns the first column of the first row, bypassing sql.DB so that
// it participates in whatever transaction is already open on conn.
func scalarOn(ctx context.Context, conn driver.Conn, statement string, args ...driver.NamedValue) (driver.Value, error) {
	queryer, ok := conn.(driver.QueryerContext)
	if !ok {
		return nil, errors.New("query: DuckDB connection does not implement driver.QueryerContext")
	}
	rows, err := queryer.QueryContext(ctx, statement, args)
	if err != nil {
		return nil, err
	}
	// Discarded deliberately: every read failure this function can suffer is already returned from
	// rows.Next below, and the single value is fully materialized before Close runs. Nothing is
	// buffered, so unlike a write path there is no flush whose failure could only surface here.
	defer func() { _ = rows.Close() }()
	values := make([]driver.Value, len(rows.Columns()))
	if err := rows.Next(values); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("query: scalar query returned no rows")
		}
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("query: scalar query returned no columns")
	}
	return values[0], nil
}

func checkCatalogOn(ctx context.Context, conn driver.Conn, refs []tableRef) error {
	for _, ref := range refs {
		value, err := scalarOn(ctx, conn, `
			SELECT coalesce(max(table_type), 'ABSENT')
			FROM information_schema.tables
			WHERE table_schema = ? AND table_name = ?`,
			driver.NamedValue{Ordinal: 1, Value: ref.SchemaName},
			driver.NamedValue{Ordinal: 2, Value: ref.TableName})
		if err != nil {
			return fmt.Errorf("query: catalog lookup failed: %w", err)
		}
		if fmt.Sprint(value) != "BASE TABLE" {
			return fmt.Errorf("%w: '%s.%s' is not a physical table", ErrAccessDenied, ref.SchemaName, ref.TableName)
		}
	}
	value, err := scalarOn(ctx, conn, `
		SELECT count(*)::BIGINT FROM duckdb_functions()
		WHERE internal = false AND function_type IN ('macro', 'table_macro')`)
	if err != nil {
		return fmt.Errorf("query: macro catalog lookup failed: %w", err)
	}
	count, ok := value.(int64)
	if !ok {
		return fmt.Errorf("query: invalid macro count type %T", value)
	}
	if count != 0 {
		return fmt.Errorf("%w: catalog contains %d user-defined macro(s)", ErrAccessDenied, count)
	}
	return nil
}
