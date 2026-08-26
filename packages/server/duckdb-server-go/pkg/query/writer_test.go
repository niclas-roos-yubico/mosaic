package query

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// cancelingWriter forwards each Write to an underlying io.Writer (bytes.Buffer here) and, once it
// has seen cancelOnCall writes, calls cancel synchronously before returning. Because this all
// happens on the same goroutine that drives writeJSONOn's drain loop -- cancel() closes the
// context's Done() channel before it returns, strictly before the loop's next call to rdr.Next()
// -- the resulting mid-drain failure is deterministic, not a timing-dependent race.
type cancelingWriter struct {
	bytes.Buffer
	cancel       context.CancelFunc
	calls        int
	cancelOnCall int
}

func (w *cancelingWriter) Write(p []byte) (int, error) {
	w.calls++
	n, err := w.Buffer.Write(p)
	if w.calls == w.cancelOnCall {
		w.cancel()
	}
	return n, err
}

// TestWriteJSONOnFailsOnMidDrainContextCancellation is the regression test for C1.
//
// The vendored driver's recordReader.Next() (github.com/duckdb/duckdb-go/v2's arrow.go) does:
//
//	select {
//	case <-r.ctx.Done():
//		r.err = r.ctx.Err()
//		return false
//	default:
//		...
//	}
//
// so once the context passed to QueryContext is done, the *next* call to Next() returns false with
// Err() set -- a shape indistinguishable, to a loop that never checks Err(), from a clean end of
// results. This test cancels the context from inside the io.Writer used for the first chunk's JSON
// bytes, guaranteeing -- deterministically, no goroutine or timing involved -- that the *second*
// call to Next() (the for-loop's own condition re-check after the first iteration's body runs)
// takes the ctx.Done() branch instead of delivering the table's later chunks.
//
// Without the `if rdr.Err() != nil` check in writeJSONOn, this fails: the function returns nil, and
// the buffer holds a syntactically valid but silently truncated JSON array -- missing every row
// after the first chunk -- which is exactly the "client sees 200 with truncated data" failure mode
// C1 describes. Verified by temporarily reverting the check: see the task's final report for the
// observed failure text.
func TestWriteJSONOnFailsOnMidDrainContextCancellation(t *testing.T) {
	db := setupTestDB(t)
	// Arrow delivers rows in fixed-size chunks (one DuckDB vector per Next() call, capped well under
	// 10000), not one row per Next() call, so a small table would land entirely in the first chunk
	// and defeat the point of this test: cancellation has to land between two chunks to produce a
	// genuine "some rows visible, later rows silently missing" truncation. 10000 rows guarantees at
	// least a second chunk exists; the last row's distinctive value is the canary that proves it
	// never got delivered.
	require.NoError(t, db.Exec(t.Context(), `CREATE TABLE many_rows AS SELECT i AS v FROM range(10000) t(i)`))

	pc, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(pc)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &cancelingWriter{cancel: cancel, cancelOnCall: 2} // call 1 is "[", call 2 is the first chunk's JSON body

	err = db.writeJSONOn(ctx, pc.arrow, `SELECT * FROM many_rows ORDER BY v`, w)
	require.Error(t, err, "writeJSONOn must surface the mid-drain cancellation instead of silently truncating the JSON array")
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, w.String(), "9999",
		"the last row must never be silently dropped from a JSON array that still looks complete")
}

// TestWriteArrowOnSurfacesCloseErrorInsteadOfDroppingIt is the regression test for I2.
//
// A zero-row result means writeArrowOn's `for rdr.Next()` loop never calls arrowWriter.Write, so
// the underlying ipc.Writer has not "started" by the time the deferred arrowWriter.Close() runs.
// arrow-go's ipc.Writer.Close calls start() in that case, which writes the schema message itself --
// so with a 0-byte limitedBuffer as the destination, the very first write Close performs fails with
// ErrResultTooLarge, entirely inside the call this test targets. That isolates the close-path
// failure from the ordinary per-record write failure a few lines above (already correctly handled,
// and already covered for a non-empty result by TestGuardedQueryRejectsOversizedArrow).
//
// Without a named return value for the error Close produces, this fails: writeArrowOn returns nil
// even though Close failed, because assigning to the old unnamed return's local `err` variable
// inside the deferred closure could never change what the function actually returned. Verified by
// temporarily reverting the fix: see the task's final report for the observed failure text.
func TestWriteArrowOnSurfacesCloseErrorInsteadOfDroppingIt(t *testing.T) {
	db := setupTestDB(t)

	pc, err := db.arrowPool.acquire(t.Context())
	require.NoError(t, err)
	defer db.arrowPool.release(pc)

	buf := newLimitedBuffer(0)
	err = db.writeArrowOn(t.Context(), pc.arrow, `SELECT 1 AS v WHERE false`, buf)
	require.Error(t, err, "writeArrowOn must surface a failed Close(), not silently return nil")
	require.ErrorIs(t, err, ErrResultTooLarge)
}
