package query

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testRelationPolicy() RelationPolicy {
	return RelationPolicy{
		ContextID:  "ctx-1",
		ValidUntil: time.Now().Add(time.Minute),
		Bindings: []AuthorizedRelation{{
			DatasetID: "dataset-1", BindingRevision: "binding-1", DataVersion: "version-1",
			SchemaName: "analytics", TableName: "orders",
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
