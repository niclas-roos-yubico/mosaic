package query

// FORK-OWNED FILE. Config, validation and route bodies for the guarded-execution coordinator: TransactionOptions is
// the guarded-mode option type; validateGuardedOptions/discardCacheIfDisabled are the bodies behind query.go's New()
// one-statement hooks; guardedJSON/guardedArrow/writeGuarded are the bodies behind query.go's four route hooks.
//
// The guard itself is state on *DB's own receiver (see query.go's `db.transaction != nil` preludes and
// transaction.go's executeGuarded) -- it is never expressed as a wrapper type constructed on top of *DB. A
// decorator shape (GuardedDB{ *DB }) was evaluated and rejected: Go has no virtual dispatch, so a decorator only
// intercepts calls made *through* the wrapper. Any call *DB makes to itself -- including the very object
// query.New(WithTransactionalCatalogGuard(...)) returns, which every caller holds unwrapped -- reaches the
// unguarded implementation with no compiler signal, no conflict, and no failing test. See AGENTS.md rule 4.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// MirrorFileRoot arms two-tier validation (view_body.go): a schema-qualified VIEW may be served when its
	// stored body reads Parquet under this prefix. Empty -- the default -- refuses every VIEW exactly as this
	// package did before. It lives here rather than on Options because a view body is only ever resolved inside
	// the guarded transaction, so a root without the guard would configure a check that never runs.
	MirrorFileRoot string
}

// guardedJSON, guardedArrow and writeGuarded are the bodies behind query.go's four route hooks. They are methods on
// upstream's own *DB, which AGENTS.md rule 3's lever allows ("methods on a type compile from any file in the
// package"), so nothing but the route DECISION stays in query.go. The decision itself cannot move here: it is the
// `db.transaction != nil` test on the receiver, and that is precisely what makes the guard reachable through every
// dispatch path -- see the rule-4 note above.
func (db *DB) guardedJSON(ctx context.Context, statement string, allowedSchemas []string) (json.RawMessage, bool, error) {
	data, err := db.executeGuarded(ctx, statement, allowedSchemas, responseJSON)
	// Always a cache miss: guarded mode requires DisableResultCache, so db.cache is nil and no guarded response is
	// ever served from, or written to, the result cache.
	return json.RawMessage(data), false, err
}

func (db *DB) guardedArrow(ctx context.Context, statement string, allowedSchemas []string) ([]byte, bool, error) {
	data, err := db.executeGuarded(ctx, statement, allowedSchemas, responseArrow)
	return data, false, err
}

// writeGuarded is the streaming-entry-point body. executeGuarded fully materializes into a byte-capped buffer and
// commits before returning, so the single w.Write below is the first byte the client can observe: nothing from a
// transaction that later rolled back ever reaches the wire.
func (db *DB) writeGuarded(ctx context.Context, statement string, allowedSchemas []string, format responseFormat, w io.Writer) error {
	data, err := db.executeGuarded(ctx, statement, allowedSchemas, format)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("query: failed to write response: %w", err)
	}
	return nil
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
	// A view body may read files, so it must never be function-unrestricted. viewBodyValidators applies an
	// allowlist unconditionally; this refuses the configuration in which that allowlist would be nothing but the
	// two Parquet readers, which is a startup failure rather than a silently very narrow boundary.
	if o.Transaction.MirrorFileRoot != "" && o.FunctionAllowlist == nil {
		return errors.New("query: a mirror file root requires a configured function allowlist")
	}
	// A root that bounds nothing is worse than no root: it reads as configured. See validateMirrorFileRoot.
	return validateMirrorFileRoot(o.Transaction.MirrorFileRoot)
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
