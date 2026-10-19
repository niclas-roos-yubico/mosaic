package server

import (
	"context"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

type relationPolicyExecutor interface {
	QueryArrowWithPolicy(context.Context, string, query.RelationPolicy) ([]byte, bool, error)
	QueryJSONWithPolicy(context.Context, string, query.RelationPolicy) ([]byte, bool, error)
}
