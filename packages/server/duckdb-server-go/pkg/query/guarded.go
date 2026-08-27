package query

// FORK-OWNED FILE. Config and validation for the guarded-execution coordinator: TransactionOptions is the
// guarded-mode option type, and validateGuardedOptions/discardCacheIfDisabled are the bodies behind query.go's
// New() one-statement hooks.
//
// The guard itself is state on *DB's own receiver (see query.go's `db.transaction != nil` preludes and
// transaction.go's executeGuarded) -- it is never expressed as a wrapper type constructed on top of *DB. A
// decorator shape (GuardedDB{ *DB }) was evaluated and rejected: Go has no virtual dispatch, so a decorator only
// intercepts calls made *through* the wrapper. Any call *DB makes to itself -- including the very object
// query.New(WithTransactionalCatalogGuard(...)) returns, which every caller holds unwrapped -- reaches the
// unguarded implementation with no compiler signal, no conflict, and no failing test. See AGENTS.md rule 4.

import (
	"errors"
	"time"

	"github.com/maypok86/otter/v2"
)

// TransactionOptions configures the bounded guarded-execution coordinator: how long a guarded query may run
// before its connection is discarded, and how many encoded bytes its response may occupy before being rejected.
type TransactionOptions struct {
	// Timeout bounds the guarded transaction's lifetime, including validation, catalog checks, and execution.
	Timeout time.Duration

	// MaxResultBytes caps the number of encoded response bytes buffered before being released to the client.
	MaxResultBytes int64
}

// validateGuardedOptions is the body behind query.go's New() one-statement guarded-option hook. It runs before any
// resource (sql.DB, connection pool, cache) is allocated, so a rejection here never leaves one behind.
func validateGuardedOptions(o *Options) error {
	if o.Transaction == nil {
		return nil
	}
	if o.Transaction.Timeout <= 0 {
		return errors.New("query: transactional catalog guard requires a positive timeout")
	}
	if o.Transaction.MaxResultBytes <= 0 {
		return errors.New("query: transactional catalog guard requires a positive max result bytes")
	}
	if !o.DisableResultCache {
		return errors.New("query: transactional catalog guard requires the result cache to be disabled")
	}
	return nil
}

// discardCacheIfDisabled is the body behind query.go's New() one-statement result-cache hook. Upstream constructs
// the otter cache unconditionally; returning nil here is what arms every `db.cache != nil` guard upstream already
// has.
func discardCacheIfDisabled(cache *otter.Cache[uint64, []byte], o *Options) *otter.Cache[uint64, []byte] {
	if o.DisableResultCache {
		return nil
	}
	return cache
}
