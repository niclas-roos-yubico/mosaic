package query

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"log/slog"
	"runtime"
	"sync"

	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/duckdb/duckdb-go/v2"
	"github.com/maypok86/otter/v2"
	"golang.org/x/sync/semaphore"
)

var ErrExecWithValidation = errors.New("query: exec command is disabled when query validation is active")

type DB struct {
	db *sql.DB

	// since db.SetMaxOpenConns doesn't apply to Arrow connections, we're using a sync.Pool to reuse connections,
	// and a semaphore to limit connections to the same as the sql.DB max connections
	connPool       *sync.Pool
	arrowSemaphore *semaphore.Weighted

	cache     *otter.Cache[uint64, []byte]
	cacheSeed maphash.Seed

	functionBlocklist           []string
	functionAllowlist           []string
	functionAllowlistConfigured bool
	rejectRemoteURILiterals     bool
	logger                      *slog.Logger

	arrowPool   *arrowPool          // FORK[arrow-pool-field]: pairs each Arrow object with the driver.Conn it was built from, which upstream's connPool cannot; only the guarded coordinator uses it
	transaction *TransactionOptions // FORK[guarded-state-field]: guard state lives on upstream's own receiver, not a wrapper type, so every dispatch path -- including New's own return value -- reaches it; see AGENTS.md rule 4
}

// New creates a new DB instance using the provided DuckDB connector, opening a sql.DB and arrow connection.
// The logger is optional; if nil, it defaults to slog.Default().
func New(ctx context.Context, connector *duckdb.Connector, opts ...OptionFunc) (*DB, error) {
	o := &Options{
		MaxConnections:  10,
		MaxCacheEntries: 1000,
		Logger:          slog.Default(),
	}
	for _, opt := range opts {
		err := opt(o)
		if err != nil {
			return nil, fmt.Errorf("query: failed to apply option: %w", err)
		}
	}
	o.FunctionBlocklist = normalizeFunctionNames(o.FunctionBlocklist)
	functionAllowlistConfigured := o.FunctionAllowlist != nil
	var functionAllowlist []string
	if functionAllowlistConfigured {
		functionAllowlist = resolveFunctionAllowlist(*o.FunctionAllowlist)
	}
	if functionAllowlistConfigured && len(o.FunctionBlocklist) > 0 {
		return nil, errors.New("query: function allowlist and blocklist cannot both be configured")
	}

	if err := validateGuardedOptions(o); err != nil { // FORK[guarded-option-validation]: must reject before any resource is allocated
		return nil, err
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(o.MaxConnections)

	arrowSemaphore := semaphore.NewWeighted(int64(o.MaxConnections))

	// the cache can be limited either by number of entries or total size in bytes
	// if both are set, MaxCacheBytes takes precedence
	cacheOpts := &otter.Options[uint64, []byte]{}

	switch {
	case o.MaxCacheBytes > 0:
		cacheOpts.MaximumWeight = uint64(o.MaxCacheBytes)
		cacheOpts.Weigher = func(key uint64, value []byte) uint32 {
			return uint32(len(value))
		}

	case o.MaxCacheEntries > 0:
		cacheOpts.MaximumSize = o.MaxCacheEntries
	}

	if o.TTL > 0 {
		cacheOpts.ExpiryCalculator = otter.ExpiryCreating[uint64, []byte](o.TTL)
	}

	cache, err := otter.New[uint64, []byte](cacheOpts)
	if err != nil {
		return nil, fmt.Errorf("query: failed to create cache: %w", err)
	}
	cache = discardCacheIfDisabled(cache, o) // FORK[result-cache-discard]: a nil db.cache is what every `db.cache != nil` guard below already keys on

	return &DB{
		db: db,

		connPool:       newArrowSyncPool(ctx, connector, o.Logger),
		arrowSemaphore: arrowSemaphore,

		cache:     cache,
		cacheSeed: maphash.MakeSeed(), // Initialize the cache seed for consistent hashing

		functionBlocklist:           append([]string(nil), o.FunctionBlocklist...),
		functionAllowlist:           append([]string(nil), functionAllowlist...),
		functionAllowlistConfigured: functionAllowlistConfigured,
		rejectRemoteURILiterals:     o.RejectRemoteURILiterals,
		logger:                      o.Logger,

		arrowPool:   newArrowPool(connector, o.MaxConnections, o.Logger), // FORK[arrow-pool-field]
		transaction: o.Transaction,                                       // FORK[guarded-state-field]
	}, nil
}

func newArrowSyncPool(ctx context.Context, connector *duckdb.Connector, logger *slog.Logger) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			conn, err := connector.Connect(ctx)
			if err != nil {
				return nil
			}

			arrow, err := duckdb.NewArrowFromConn(conn)
			if err != nil {
				return nil
			}

			runtime.AddCleanup(arrow, func(driverConn driver.Conn) {
				closeErr := driverConn.Close()
				if closeErr != nil {
					logger.Error("query: failed to close Arrow connection", "error", closeErr)
				}
			}, conn)

			return arrow
		},
	}
}

func (db *DB) getArrowConn(ctx context.Context) (*duckdb.Arrow, error) {
	err := db.arrowSemaphore.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("query: failed to acquire connection: %w", err)
	}

	untypedArrow := db.connPool.Get()
	if untypedArrow == nil {
		return nil, fmt.Errorf("query: failed to get Arrow connection from pool")
	}

	arrow, ok := untypedArrow.(*duckdb.Arrow)
	if !ok {
		return nil, fmt.Errorf("query: invalid type in Arrow connection pool")
	}

	return arrow, nil
}

func (db *DB) putArrowConn(arrow *duckdb.Arrow) {
	db.connPool.Put(arrow)
	db.arrowSemaphore.Release(1)
}

type Extension struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Repository  string `json:"repository"`
	InstallMode string `json:"install_mode"`
}

func (db *DB) GetExtensions(ctx context.Context) ([]Extension, error) {
	const stmt = `SELECT extension_name, extension_version, installed_from, install_mode
FROM duckdb_extensions()
WHERE install_mode != 'NOT_INSTALLED'`

	rows, err := db.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("query: failed to get extensions: %w", err)
	}
	defer rows.Close()

	var extensions []Extension
	for rows.Next() {
		var ext Extension
		err = rows.Scan(&ext.Name, &ext.Version, &ext.Repository, &ext.InstallMode)
		if err != nil {
			return nil, fmt.Errorf("query: failed to scan extension row: %w", err)
		}

		extensions = append(extensions, ext)
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("query: error during rows iteration: %w", err)
	}

	return extensions, nil
}

// Close closes any resources created by New, but does not close the underlying connector.
func (db *DB) Close() {
	err := db.db.Close()
	if err != nil {
		db.logger.Error("failed to close database", "error", err)
	}
}

func (db *DB) Exec(ctx context.Context, query string) error {
	// FORK[exec-denial-guarded]: exec gate 3. It has to be a term in upstream's own condition because the denial must
	// hold for every holder of the *DB, including the one New returns; a fork-owned wrapper would not bind it.
	if db.transaction != nil || len(db.functionBlocklist) > 0 || db.functionAllowlistConfigured || db.rejectRemoteURILiterals {
		return ErrExecWithValidation
	}

	_, err := db.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("query: failed to execute query: %w", err)
	}

	return nil
}

// FORK[validators-extract]: validator construction extracted so validateQueryOn builds the identical set;
// duplicating the list fork-side would silently omit any validator upstream later adds. Extracted adjacently.
func (db *DB) newValidators(allowedSchemas []string) []Validator {
	validators := make([]Validator, 0, 4)
	if len(allowedSchemas) > 0 {
		validators = append(validators, newBaseTableValidator(allowedSchemas))
		// FORK[cte-scope-validator]: kept as a second, independent validator beside upstream's rather than folded into it --
		// upstream's CTE exemption is scope-blind (platform#8k4b) and only a denial it cannot reach fixes that. Body in cte_scope.go.
		validators = append(validators, newCTEScopeValidator())
	}
	if len(db.functionBlocklist) > 0 {
		validators = append(validators, newFunctionBlocklistValidator(db.functionBlocklist))
	}
	if db.functionAllowlistConfigured {
		validators = append(validators, newFunctionAllowlistValidator(db.functionAllowlist))
	}
	if db.rejectRemoteURILiterals {
		validators = append(validators, newRemoteURILiteralValidator())
	}
	return validators
}

func (db *DB) validateQuery(ctx context.Context, query string, allowedSchemas []string) error {
	validators := db.newValidators(allowedSchemas)
	if len(validators) == 0 {
		return nil
	}

	err := db.ValidateSQL(ctx, query, validators...)
	if err != nil {
		return fmt.Errorf("query: validation failed: %w", err)
	}

	return nil
}

func (db *DB) QueryJSON(ctx context.Context, query string, allowedSchemas []string, useCache bool) (json.RawMessage, bool, error) {
	// FORK[guarded-route-queryjson]: the route decision must stay on upstream's own receiver -- state every dispatch
	// path reaches, including a call *DB makes to itself. Body in guarded.go; upstream's path below is untouched.
	if db.transaction != nil {
		return db.guardedJSON(ctx, query, allowedSchemas)
	}

	err := db.validateQuery(ctx, query, allowedSchemas)
	if err != nil {
		return nil, false, err
	}

	var key uint64
	var data []byte

	if useCache && db.cache != nil {
		key, data = db.cacheGet("j", query)
		if data != nil {
			return data, true, nil
		}
	}

	var buf bytes.Buffer

	err = db.writeJSON(ctx, query, &buf)
	if err != nil {
		return nil, false, err
	}

	if useCache && db.cache != nil {
		db.cacheSet(key, buf.Bytes())
	}

	return buf.Bytes(), false, nil
}

func (db *DB) WriteJSON(ctx context.Context, query string, allowedSchemas []string, w io.Writer) error {
	// FORK[guarded-route-writejson]: route decision on upstream's receiver, body in guarded.go. Mirrors QueryJSON.
	if db.transaction != nil {
		return db.writeGuarded(ctx, query, allowedSchemas, responseJSON, w)
	}

	err := db.validateQuery(ctx, query, allowedSchemas)
	if err != nil {
		return err
	}

	return db.writeJSON(ctx, query, w)
}

// SECURITY: writeJSON executes without policy validation. Call it only after validateQuery succeeds for the same query
// and request-scoped allowed schemas.
func (db *DB) writeJSON(ctx context.Context, query string, w io.Writer) error {
	arrow, err := db.getArrowConn(ctx)
	if err != nil {
		return err
	}
	defer db.putArrowConn(arrow)

	return db.writeJSONOn(ctx, arrow, query, w) // FORK[encoder-extract]: body extracted so the guarded coordinator reuses one encoder
}

// FORK[encoder-extract]: extracted from writeJSON's body so the guarded coordinator in transaction.go encodes onto
// the pooledArrowConn.arrow it already holds, without a second pool acquisition. Kept adjacent in this upstream file
// deliberately: relocating it to a fork-owned file costs +60 deletions (AGENTS.md rule 3).
//
// FORK[encoder-extract] fix wave C1: the rdr.Err() check below is load-bearing. The vendored driver's recordReader.Next() returns
// false both on a clean end of results and on a mid-drain cancel or timeout, setting Err() only in the latter, so
// without it "]" would close a valid-looking but truncated JSON array that executeGuarded commits and returns.
func (db *DB) writeJSONOn(ctx context.Context, arrowConn *duckdb.Arrow, statement string, w io.Writer) error {
	rdr, err := arrowConn.QueryContext(ctx, statement)
	if err != nil {
		return fmt.Errorf("query: failed to execute query: %w", err)
	}
	defer rdr.Release()

	_, err = w.Write([]byte("["))
	if err != nil {
		return fmt.Errorf("query: failed to write start of JSON array: %w", err)
	}

	for i := 0; rdr.Next(); i++ {
		if i > 0 {
			_, err = w.Write([]byte(","))
			if err != nil {
				return fmt.Errorf("query: failed to write comma between records: %w", err)
			}
		}

		var jsonBytes []byte
		jsonBytes, err = rdr.RecordBatch().MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to marshal record to JSON: %w", err)
		}

		// a record is a batch of rows, and MarshalJSON returns a JSON array of objects. If there are multiple records,
		// we want a combined JSON array of objects, not an array of arrays, so we trim the outer brackets
		_, err = w.Write(jsonBytes[1 : len(jsonBytes)-1])
		if err != nil {
			return fmt.Errorf("failed to write JSON to writer: %w", err)
		}
	}

	if rdr.Err() != nil {
		return fmt.Errorf("query: error during record iteration: %w", rdr.Err())
	}

	_, err = w.Write([]byte("]"))
	if err != nil {
		return fmt.Errorf("query: failed to write end of JSON array: %w", err)
	}

	return nil
}

func (db *DB) QueryArrow(ctx context.Context, query string, allowedSchemas []string, useCache bool) ([]byte, bool, error) {
	// FORK[guarded-route-queryarrow]: route decision on upstream's receiver, body in guarded.go. Mirrors QueryJSON.
	if db.transaction != nil {
		return db.guardedArrow(ctx, query, allowedSchemas)
	}

	err := db.validateQuery(ctx, query, allowedSchemas)
	if err != nil {
		return nil, false, err
	}

	var key uint64
	var data []byte

	if useCache && db.cache != nil {
		key, data = db.cacheGet("a", query)
		if data != nil {
			return data, true, nil
		}
	}

	var buf bytes.Buffer

	err = db.writeArrow(ctx, query, &buf)
	if err != nil {
		return nil, false, err
	}

	if useCache && db.cache != nil {
		db.cacheSet(key, buf.Bytes())
	}

	return buf.Bytes(), false, nil
}

func (db *DB) WriteArrow(ctx context.Context, query string, allowedSchemas []string, w io.Writer) error {
	// FORK[guarded-route-writearrow]: route decision on upstream's receiver, body in guarded.go. Mirrors WriteJSON.
	if db.transaction != nil {
		return db.writeGuarded(ctx, query, allowedSchemas, responseArrow, w)
	}

	err := db.validateQuery(ctx, query, allowedSchemas)
	if err != nil {
		return err
	}

	return db.writeArrow(ctx, query, w)
}

// SECURITY: writeArrow executes without policy validation. Call it only after validateQuery succeeds for the same query
// and request-scoped allowed schemas.
func (db *DB) writeArrow(ctx context.Context, query string, w io.Writer) error {
	arrow, err := db.getArrowConn(ctx)
	if err != nil {
		return err
	}
	defer db.putArrowConn(arrow)

	return db.writeArrowOn(ctx, arrow, query, w) // FORK[encoder-extract]: body extracted so the guarded coordinator reuses one encoder
}

// FORK[encoder-extract]: extracted from writeArrow's body for the same reason as writeJSONOn above, and kept
// adjacent here for the same rule-3 adjacency cost.
//
// FORK[encoder-extract] fix wave I2: the return value is named because the deferred Close below can fail -- writing the Arrow
// end-of-stream marker can cross the transaction's MaxResultBytes limit -- and with an unnamed return, assigning to
// the loop's `err` inside the deferred closure was a dead store, letting a truncated Arrow IPC stream commit and
// reach the client as 200 instead of 413. retErr is overwritten only while nil, so an earlier error is never masked.
func (db *DB) writeArrowOn(ctx context.Context, arrowConn *duckdb.Arrow, statement string, w io.Writer) (retErr error) {
	rdr, err := arrowConn.QueryContext(ctx, statement)
	if err != nil {
		return fmt.Errorf("query: failed to execute query: %w", err)
	}
	defer rdr.Release()

	arrowWriter := ipc.NewWriter(w, ipc.WithSchema(rdr.Schema()))
	defer func() {
		if cerr := arrowWriter.Close(); cerr != nil {
			if retErr == nil {
				retErr = fmt.Errorf("query: failed to close Arrow writer: %w", cerr)
			} else {
				db.logger.Error("query: failed to close Arrow writer", "error", cerr)
			}
		}
	}()

	for rdr.Next() {
		err = arrowWriter.Write(rdr.RecordBatch())
		if err != nil {
			return fmt.Errorf("query: failed to write record: %w", err)
		}
	}
	if rdr.Err() != nil {
		return fmt.Errorf("query: error during record iteration: %w", rdr.Err())
	}

	return nil
}

// cacheGet always returns a key, and either the cached data or nil if not found
func (db *DB) cacheGet(format, query string) (uint64, []byte) {
	// the key has to be different based on the output data type, so we can cache arrow and json separately
	key := maphash.String(db.cacheSeed, query+format)

	entry, ok := db.cache.GetEntry(key)
	if ok {
		return key, entry.Value
	}

	return key, nil
}

func (db *DB) cacheSet(key uint64, data []byte) {
	db.cache.Set(key, data)
}
