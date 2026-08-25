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
	defer rows.Close()
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
