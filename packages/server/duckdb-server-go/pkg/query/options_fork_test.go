package query

import (
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"
)

// Fork-owned home for the transactional catalog guard's option-validation test. It lived in
// upstream's options_test.go until 2026-08-27, where it was pure carrying cost: AGENTS.md rule 3
// names the bottom of an upstream _test.go as exactly where the next upstream test will land, and
// the marker that recorded it as a fork edit had been dropped, leaving 22 lines of fork test with
// no inventory trail. Moving it costs nothing -- same package, no call site left behind -- and
// returns options_test.go to byte-identical with upstream.
//
// This is the runtime half of the guarded-option-validation hook's cover; guard_shape_fork_test.go's
// TestQueryGoRetainsNewConstructorHooks is the source half.
func TestTransactionalGuardRequiresPositiveLimitsAndDisabledCache(t *testing.T) {
	connector, err := duckdb.NewConnector(":memory:", nil)
	require.NoError(t, err)
	defer func() { _ = connector.Close() }()
	for name, options := range map[string][]OptionFunc{
		"zero timeout":  {WithResultCacheDisabled(), WithTransactionalCatalogGuard(TransactionOptions{MaxResultBytes: 1})},
		"zero bytes":    {WithResultCacheDisabled(), WithTransactionalCatalogGuard(TransactionOptions{Timeout: time.Second})},
		"cache enabled": {WithTransactionalCatalogGuard(TransactionOptions{Timeout: time.Second, MaxResultBytes: 1})},
	} {
		t.Run(name, func(t *testing.T) {
			db, err := New(t.Context(), connector, options...)
			require.Error(t, err)
			if db != nil {
				db.Close()
			}
		})
	}
}
