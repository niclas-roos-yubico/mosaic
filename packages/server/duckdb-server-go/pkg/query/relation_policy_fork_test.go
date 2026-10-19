package query

import (
	"context"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/duckdb/duckdb-go/v2"
	"github.com/stretchr/testify/require"
)

func testRelationPolicy() RelationPolicy {
	return RelationPolicy{
		ContextID:  "ctx-1",
		ValidUntil: time.Now().Add(time.Minute),
		Bindings: []AuthorizedRelation{{
			DatasetID: "dataset-1", MirrorID: "mirror-1", BindingRevision: "binding-1", DataVersion: "1",
			SchemaName: "analytics", TableName: "orders", Prefix: "mirror/prefix-a",
		}},
	}
}

func TestRelationPolicyRequiresTrustedBindingFields(t *testing.T) {
	policy := testRelationPolicy()
	require.NoError(t, policy.Validate())

	policy.Bindings[0].DataVersion = ""
	require.ErrorIs(t, policy.Validate(), ErrAccessDenied)

	policy = testRelationPolicy()
	policy.Bindings[0].SchemaName = ""
	require.ErrorIs(t, policy.Validate(), ErrAccessDenied)
}

func TestRelationPolicyValidatorAllowsOnlyExactRelationsAndCTEs(t *testing.T) {
	validator := newRelationPolicyValidator(testRelationPolicy().Bindings)
	validator.CheckNode(map[string]any{"type": "BASE_TABLE", "schema_name": "schema_name:analytics", "table_name": "orders"}, nil)
	validator.CheckNode(map[string]any{"type": "BASE_TABLE", "schema_name": "schema_name:analytics", "table_name": "payments"}, nil)
	validator.CheckNode(map[string]any{"type": "BASE_TABLE", "table_name": "rows"}, nil)
	validator.CheckNode(map[string]any{"key": "rows"}, []string{"cte_map", "map"})

	errs := validator.Validate()
	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], ErrAccessDenied)
	require.Contains(t, errs[0].Error(), "payments")
}

func TestRelationPolicyValidatorRejectsCatalogMetadata(t *testing.T) {
	validator := newRelationPolicyValidator(testRelationPolicy().Bindings)
	validator.CheckNode(map[string]any{"type": "SHOW_REF", "schema_name": "schema_name:analytics"}, nil)
	require.Len(t, validator.Validate(), 1)
}

func TestRelationPolicyExpiryIsBounded(t *testing.T) {
	policy := testRelationPolicy()
	policy.ValidUntil = time.Now().Add(-time.Second)
	require.ErrorIs(t, policy.Validate(), ErrPolicyExpired)
}

func TestGuardedRelationPolicyEnforcesSiblingAndBindingChecks(t *testing.T) {
	var verifierCalls int
	db, _ := guardedTransactionDB(t,
		`CREATE SCHEMA analytics; CREATE TABLE analytics.orders(v INTEGER); INSERT INTO analytics.orders VALUES (7); CREATE TABLE analytics.payments(v INTEGER); INSERT INTO analytics.payments VALUES (9)`,
		TransactionOptions{
			Timeout:        time.Second,
			MaxResultBytes: 1 << 20,
			BindingVerifier: func(context.Context, driver.Conn, RelationPolicy) error {
				verifierCalls++
				return nil
			},
		})
	policy := testRelationPolicy()

	data, _, err := db.QueryJSONWithPolicy(t.Context(), `SELECT * FROM analytics.payments`, policy)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Empty(t, data)
	require.Zero(t, verifierCalls, "the binding verifier must not run after exact relation denial")

	data, _, err = db.QueryJSONWithPolicy(t.Context(), `SELECT * FROM analytics.orders`, policy)
	require.NoError(t, err)
	require.Contains(t, string(data), "7")
	require.Equal(t, 1, verifierCalls)
}

func TestRelationPolicyRejectsUnguardedDatabase(t *testing.T) {
	db, _ := transactionTestDB(t, WithMaxConnections(1))
	_, _, err := db.QueryJSONWithPolicy(t.Context(), `SELECT 1`, testRelationPolicy())
	require.ErrorIs(t, err, ErrAccessDenied)
}

func TestMirrorBindingVerifierPinsVersionAndPrefixOnGuardedConnection(t *testing.T) {
	db, connector, prefix, _ := mirrorViewDB(t, false)
	policy := testRelationPolicy()
	policy.Bindings[0].Prefix = prefix

	data, _, err := db.QueryJSONWithPolicy(t.Context(), `SELECT * FROM analytics.orders`, policy)
	require.NoError(t, err)
	require.Contains(t, string(data), "7")

	conn, err := connector.Connect(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	execer, ok := conn.(driver.ExecerContext)
	require.True(t, ok)
	_, err = execer.ExecContext(t.Context(), `UPDATE bqsync_internal.mirror_state SET prefix = 'stale-prefix' WHERE import_id = 'mirror-1'`, nil)
	require.NoError(t, err)

	data, _, err = db.QueryJSONWithPolicy(t.Context(), `SELECT * FROM analytics.orders`, policy)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Empty(t, data)
}

func TestMirrorBindingVerifierRejectsCatalogViewRepoint(t *testing.T) {
	db, _, prefix, decoy := mirrorViewDB(t, true)
	policy := testRelationPolicy()
	policy.Bindings[0].Prefix = prefix

	data, _, err := db.QueryJSONWithPolicy(t.Context(), `SELECT * FROM analytics.orders`, policy)
	require.ErrorIs(t, err, ErrAccessDenied)
	require.Empty(t, data)
	_ = decoy
}

func TestRelationPolicyAllowsMetadataOnlyForTheExactBoundRelation(t *testing.T) {
	db, _, prefix, _ := mirrorViewDB(t, false)
	policy := testRelationPolicy()
	policy.Bindings[0].Prefix = prefix

	for _, sql := range []string{
		`DESCRIBE SELECT * FROM analytics.orders`,
		`SUMMARIZE SELECT * FROM analytics.orders`,
		`DESCRIBE SELECT * FROM "analytics"."orders"`,
		`SUMMARIZE SELECT * FROM "analytics"."orders"`,
	} {
		data, _, err := db.QueryJSONWithPolicy(t.Context(), sql, policy)
		require.NoError(t, err, sql)
		require.NotEmpty(t, data, sql)
	}

	for _, sql := range []string{
		`DESCRIBE SELECT * FROM analytics.payments`,
		`SUMMARIZE SELECT * FROM analytics.payments`,
		`DESCRIBE SELECT * FROM "analytics"."payments"`,
		`SUMMARIZE SELECT * FROM "analytics"."payments"`,
	} {
		data, _, err := db.QueryJSONWithPolicy(t.Context(), sql, policy)
		require.ErrorIs(t, err, ErrAccessDenied, sql)
		require.Empty(t, data, sql)
	}
}

func mirrorViewDB(t *testing.T, repointed bool) (*DB, *duckdb.Connector, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guarded.duckdb")
	root := t.TempDir()
	prefix := filepath.Join(root, "mirror-1", "version-1")
	decoy := filepath.Join(root, "mirror-2", "version-2")
	require.NoError(t, os.MkdirAll(prefix, 0o700))
	require.NoError(t, os.MkdirAll(decoy, 0o700))
	seedConnector, err := duckdb.NewConnector(path, nil)
	require.NoError(t, err)
	seed, err := New(t.Context(), seedConnector)
	require.NoError(t, err)
	require.NoError(t, seed.Exec(t.Context(), `CREATE SCHEMA bqsync_internal; CREATE TABLE bqsync_internal.mirror_state(import_id VARCHAR PRIMARY KEY, version BIGINT, prefix VARCHAR); CREATE SCHEMA analytics`))
	for _, dir := range []string{prefix, decoy} {
		require.NoError(t, seed.Exec(t.Context(), fmt.Sprintf(`COPY (SELECT 7 AS v) TO %s (FORMAT PARQUET)`, quoteLiteral(filepath.Join(dir, "data.parquet")))))
	}
	require.NoError(t, seed.Exec(t.Context(), fmt.Sprintf(`INSERT INTO bqsync_internal.mirror_state VALUES ('mirror-1', 1, %s); CREATE VIEW analytics.orders AS SELECT * FROM read_parquet(%s)`, quoteLiteral(prefix), quoteLiteral(filepath.Join(map[bool]string{false: prefix, true: decoy}[repointed], "*.parquet")))))
	seed.Close()
	require.NoError(t, seedConnector.Close())
	connector, err := duckdb.NewConnector(path, nil)
	require.NoError(t, err)
	db, err := New(t.Context(), connector, WithMaxConnections(1), WithResultCacheDisabled(),
		WithFunctionAllowlist(FunctionAllowlistOptions{Include: []string{"read_parquet"}}),
		WithTransactionalCatalogGuard(TransactionOptions{Timeout: time.Second, MaxResultBytes: 1 << 20, MirrorFileRoot: root, BindingVerifier: MirrorBindingVerifier}))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); require.NoError(t, connector.Close()) })
	return db, connector, prefix, decoy
}
