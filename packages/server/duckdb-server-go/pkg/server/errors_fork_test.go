package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

// Guarded-execution coordinator error mapping; see errors.go's classifyError.
// Fork-owned file per AGENTS.md rule 3: upstream appends to its own test files
// most freely, so a fork test at the bottom of server_test.go sits exactly
// where the next upstream test will land.

func TestClassifyResultTooLarge(t *testing.T) {
	got := classifyError(query.ErrResultTooLarge)
	require.Equal(t, http.StatusRequestEntityTooLarge, got.status)
	require.Equal(t, "response_too_large", got.code)
}

func TestClassifyQueryTimeout(t *testing.T) {
	got := classifyError(query.ErrQueryTimeout)
	require.Equal(t, http.StatusGatewayTimeout, got.status)
	require.Equal(t, "query_timeout", got.code)
}
