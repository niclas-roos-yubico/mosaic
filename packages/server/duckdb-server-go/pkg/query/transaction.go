package query

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// responseFormat distinguishes the two encodings executeGuarded can produce, so it can select the right encoder
// and cache key without a second type parameter.
type responseFormat string

const (
	responseJSON  responseFormat = "j"
	responseArrow responseFormat = "a"
)

// txGuard ensures exactly one of Commit or Rollback ever reaches the underlying driver.Tx. The duckdb driver
// panics ("misuse of duckdb driver: extra Commit/Rollback") if either is called after the transaction has already
// been finished, and without this guard the watchdog goroutine's timeout-triggered Rollback can race the main
// flow's own success-path Commit call at the exact instant the guard deadline elapses: both sides would otherwise
// call a terminal method on the same driver.Tx concurrently. Every path that finishes the transaction — the
// watchdog and executeGuarded alike — must go through commit/rollback here instead of calling tx directly.
type txGuard struct {
	tx   driver.Tx
	mu   sync.Mutex
	done bool
}

func newTxGuard(tx driver.Tx) *txGuard {
	return &txGuard{tx: tx}
}

// commit finishes the transaction with Commit. ok is false if the transaction was already finished by a
// concurrent rollback (the watchdog won the race): the caller's buffered result was never actually made durable
// and must be discarded rather than treated as a success.
func (g *txGuard) commit() (ok bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return false, nil
	}
	g.done = true
	return true, g.tx.Commit()
}

// rollback finishes the transaction with Rollback, unless it was already finished by a prior commit or rollback,
// in which case it is a safe no-op. ok reports whether this call was the one that actually performed the
// rollback, so callers (specifically executeGuarded's cleanup) can tell "I rolled it back" from "it was already
// finished" without risking a second driver call either way. err is the driver's Rollback error (nil when ok is
// false, since no driver call was made): the duckdb driver clears its internal "in transaction" bookkeeping before
// issuing ROLLBACK, so a failed Rollback leaves the physical connection genuinely still inside a DuckDB
// transaction even though the driver believes otherwise. A caller that returns such a connection to the pool
// would have its next BeginTx fail; see the reusable = false handling at this method's call site in
// executeGuarded's deferred cleanup below.
func (g *txGuard) rollback() (ok bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return false, nil
	}
	g.done = true
	return true, g.tx.Rollback()
}

// watchTransaction starts a goroutine that rolls back the transaction behind guard if ctx is done before stop is
// called. It returns rolledBack, which reports whether the watchdog itself actually performed the rollback (as
// opposed to losing the race to the main flow finishing first), and stop, which must be called on every exit
// path: stop is idempotent and blocks until the watcher goroutine has actually exited, so it never leaks a
// goroutine and callers can safely inspect rolledBack immediately after stop returns.
func watchTransaction(ctx context.Context, guard *txGuard) (*atomic.Bool, func()) {
	rolledBack := &atomic.Bool{}
	stopCh := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() { close(stopCh) })
		<-exited
	}
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			// The watchdog path is already contained regardless of whether the driver's Rollback call itself
			// succeeds: watchdogRolledBack becoming true unconditionally forces reusable = false in
			// executeGuarded's cleanup below, so a failed Rollback's error is intentionally not inspected here.
			if ok, _ := guard.rollback(); ok {
				rolledBack.Store(true)
			}
		case <-stopCh:
		}
	}()
	return rolledBack, stop
}

// executeGuarded is the bounded, authorized coordinator for guarded mode (db.transaction != nil). It:
//
//  1. cheaply pre-validates on db.db (the *sql.DB), before touching the Arrow pool, for load shedding;
//  2. acquires exactly one pooledArrowConn from db.arrowPool;
//  3. begins a transaction on that connection's driver.Conn;
//  4. runs authoritative validation as the FIRST statement after BEGIN, which pins the DuckDB snapshot;
//  5. checks the live catalog on the same connection/transaction;
//  6. executes and fully materializes the response into a byte-capped buffer;
//  7. commits;
//  8. only then returns the response bytes for the caller to write to the network.
//
// Ordering above is the security property: validation must be the first statement after BeginTx, catalog
// authorization must precede any cache read, and the response must be committed before any byte reaches the
// client.
func (db *DB) executeGuarded(ctx context.Context, statement string, schemas []string, format responseFormat) ([]byte, error) {
	// I3: newValidators (query.go) only installs the base-table validator when len(allowedSchemas) > 0, so an
	// empty schemas here would leave only the function allowlist, URI-literal rejection, and the catalog's
	// physical-table check active -- none of which asks "is this schema authorized?" -- and checkCatalogOn would
	// happily confirm any physical table in any schema. Not reachable through the shipped binary today
	// (server.WithSchemaResolver rejects a nil resolver, the JWT validator requires a non-empty allowed_schemas
	// claim, and requestSchemas 401s on an empty list), but this package's core guarantee should not depend on a
	// caller elsewhere doing the right thing.
	if len(schemas) == 0 {
		return nil, fmt.Errorf("%w: guarded execution requires at least one authorized schema", ErrAccessDenied)
	}

	guardCtx, cancel := context.WithTimeout(ctx, db.transaction.Timeout)
	defer cancel()

	// Cheap load-shedding validation uses sql.DB before Arrow acquisition. This deliberately runs before any
	// pool acquisition below: db.db must never be touched again once a pooledArrowConn is held, or a pool-size-one
	// deployment can deadlock a request against itself.
	if err := db.validateQuery(guardCtx, statement, schemas); err != nil {
		return nil, normalizeGuardError(guardCtx, err)
	}

	pc, err := db.arrowPool.acquire(guardCtx)
	if err != nil {
		return nil, normalizeGuardError(guardCtx, err)
	}
	reusable := true
	defer func() {
		if reusable {
			db.arrowPool.release(pc)
		} else {
			db.arrowPool.discard(pc)
		}
	}()

	tx, err := pc.conn.(driver.ConnBeginTx).BeginTx(guardCtx, driver.TxOptions{})
	if err != nil {
		// The connection never entered a transaction, but its state after a failed BeginTx is not something we
		// validate here, so it is discarded rather than returned to the pool.
		reusable = false
		return nil, fmt.Errorf("query: begin guarded transaction: %w", err)
	}

	guard := newTxGuard(tx)
	watchdogRolledBack, stopWatchdog := watchTransaction(guardCtx, guard)
	finished := false
	defer func() {
		// stopWatchdog blocks until the watcher goroutine has fully exited, so watchdogRolledBack.Load() below is
		// race-free. guard.rollback() is always safe to call here even if the watchdog (or a lost commit race
		// below) already finished the transaction: txGuard makes that a no-op instead of a second driver call.
		stopWatchdog()
		if !finished {
			// M3: a failed Rollback leaves the physical connection still inside a DuckDB transaction even
			// though txGuard now considers it finished (the driver clears its own bookkeeping before issuing
			// ROLLBACK). Returning such a connection to the pool would make the next request's BeginTx fail,
			// so discard it instead.
			if _, rerr := guard.rollback(); rerr != nil {
				reusable = false
			}
		}
		if watchdogRolledBack.Load() {
			reusable = false
		}
	}()

	// FIRST statement after BEGIN: this pins the DuckDB snapshot. Nothing may run on pc.conn before this.
	refs, err := db.validateQueryOn(guardCtx, pc.conn, statement, schemas)
	if err != nil {
		return nil, normalizeGuardError(guardCtx, err)
	}
	if err := db.checkCatalogOn(guardCtx, pc.conn, refs, schemas); err != nil {
		return nil, normalizeGuardError(guardCtx, err)
	}

	// CONTROLLER RULING: this branch is unreachable by construction. New rejects Transaction != nil &&
	// !DisableResultCache, so whenever executeGuarded runs, db.cache is always nil (see New). It is kept,
	// unmodified, because it encodes the ordering the design rests on: if guarded mode ever grew a cache, the
	// authoritative validation and live catalog check above must still run before any cache read, never after.
	// Deleting the branch would delete that documented invariant along with the dead code.
	if db.cache != nil {
		if _, cached := db.cacheGet(string(format), statement); cached != nil {
			return cached, nil
		}
	}

	buffer := newLimitedBuffer(db.transaction.MaxResultBytes)
	switch format {
	case responseJSON:
		err = db.writeJSONOn(guardCtx, pc.arrow, statement, buffer)
	case responseArrow:
		err = db.writeArrowOn(guardCtx, pc.arrow, statement, buffer)
	default:
		err = fmt.Errorf("query: unknown response format %q", format)
	}
	if err != nil {
		return nil, normalizeGuardError(guardCtx, err)
	}

	committed, err := guard.commit()
	if err != nil {
		// A failed commit leaves the connection in an unknown state: discard it rather than returning it to the
		// pool for reuse.
		reusable = false
		return nil, normalizeGuardError(guardCtx, err)
	}
	if !committed {
		// The watchdog rolled back this transaction concurrently with this very commit attempt (the guard
		// deadline elapsed at the instant execution finished): the buffered result was never made durable, so it
		// must not be returned as if it were. watchdogRolledBack is guaranteed true here, so the deferred cleanup
		// above will discard the connection.
		return nil, normalizeGuardError(guardCtx, guardCtx.Err())
	}
	finished = true

	// Copy out of buffer before it (and the pooledArrowConn's Arrow-backed memory it was filled from) can be
	// reused: the caller must not retain any reference into pool-owned state.
	return append([]byte(nil), buffer.Bytes()...), nil
}

func normalizeGuardError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrQueryTimeout, err)
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("query: request canceled: %w", context.Canceled)
	}
	return err
}
