package query

import (
	"context"
	"database/sql/driver"
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/duckdb/duckdb-go/v2"
	"golang.org/x/sync/semaphore"
)

// pooledArrowConn pairs a duckdb.Arrow object with the exact driver.Conn it was constructed from, so that a
// transaction begun on conn is the same transaction arrow executes queries in.
type pooledArrowConn struct {
	conn    driver.Conn
	arrow   *duckdb.Arrow
	cleanup runtime.Cleanup
}

// arrowCleanupState is captured by the runtime.AddCleanup closure. It must never reference the *pooledArrowConn
// itself: capturing that pointer would keep the guarded object permanently reachable and the cleanup would never run.
type arrowCleanupState struct {
	conn   driver.Conn
	logger *slog.Logger
}

// arrowPool hands out pooledArrowConn instances, limiting the number of concurrently live connections to max via a
// semaphore (since sql.DB's connection limit does not apply to these directly-managed Arrow connections).
type arrowPool struct {
	connector *duckdb.Connector
	items     sync.Pool
	limit     *semaphore.Weighted
	logger    *slog.Logger
}

func newArrowPool(connector *duckdb.Connector, max int, logger *slog.Logger) *arrowPool {
	return &arrowPool{connector: connector, limit: semaphore.NewWeighted(int64(max)), logger: logger}
}

// acquire reserves one of the pool's permits and returns a pooledArrowConn, either reused from the pool or newly
// created. Every error path releases the permit it took before returning, so a failed acquire never leaks one.
func (p *arrowPool) acquire(ctx context.Context) (*pooledArrowConn, error) {
	if err := p.limit.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("query: failed to acquire connection: %w", err)
	}
	if item := p.items.Get(); item != nil {
		return item.(*pooledArrowConn), nil
	}
	conn, err := p.connector.Connect(ctx)
	if err != nil {
		p.limit.Release(1)
		return nil, fmt.Errorf("query: failed to connect Arrow connection: %w", err)
	}
	arrowConn, err := duckdb.NewArrowFromConn(conn)
	if err != nil {
		_ = conn.Close()
		p.limit.Release(1)
		return nil, fmt.Errorf("query: failed to construct Arrow connection: %w", err)
	}
	pc := &pooledArrowConn{conn: conn, arrow: arrowConn}
	pc.cleanup = runtime.AddCleanup(pc, func(state arrowCleanupState) {
		if err := state.conn.Close(); err != nil {
			state.logger.Error("query: failed to close Arrow connection", "error", err)
		}
	}, arrowCleanupState{conn: conn, logger: p.logger})
	return pc, nil
}

// release returns a healthy pooledArrowConn to the pool for reuse and frees its permit.
func (p *arrowPool) release(pc *pooledArrowConn) {
	p.items.Put(pc)
	p.limit.Release(1)
}

// discard permanently closes a pooledArrowConn instead of returning it to the pool (e.g. because it is no longer
// known to be healthy) and frees its permit. It stops the finalizer cleanup first so the connection is not closed
// twice.
func (p *arrowPool) discard(pc *pooledArrowConn) {
	pc.cleanup.Stop()
	if err := pc.conn.Close(); err != nil {
		p.logger.Error("query: failed to discard Arrow connection", "error", err)
	}
	p.limit.Release(1)
}
