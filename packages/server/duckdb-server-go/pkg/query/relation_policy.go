package query

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/functionset/remoteread"
)

var ErrPolicyExpired = errors.New("query: authorization policy expired")

// AuthorizedRelation is the trusted relation binding issued by the platform
// authorizer. BindingRevision and DataVersion are opaque to Mosaic; the
// configured verifier checks them against the mirror catalog on the guarded
// connection before execution.
type AuthorizedRelation struct {
	DatasetID       string
	MirrorID        string
	BindingRevision string
	DataVersion     string
	SchemaName      string
	TableName       string
	Prefix          string
}

// RelationPolicy is the per-request authorization snapshot for public Mosaic
// queries. Its bindings are mandatory and are never inferred from request SQL.
type RelationPolicy struct {
	ContextID  string
	ValidUntil time.Time
	Bindings   []AuthorizedRelation
}

// RelationBindingVerifier validates the context and trusted source/version
// bindings while the query transaction is open. It must read only from conn
// and return an error when the context or any binding is no longer current.
type RelationBindingVerifier func(context.Context, driver.Conn, RelationPolicy) error

func (p RelationPolicy) validate(now time.Time) error {
	if p.ContextID == "" {
		return fmt.Errorf("%w: authorization context is required", ErrAccessDenied)
	}
	if len(p.Bindings) == 0 {
		return fmt.Errorf("%w: relation bindings are required", ErrAccessDenied)
	}
	if p.ValidUntil.IsZero() {
		return fmt.Errorf("%w: policy expiry is required", ErrAccessDenied)
	}
	if !now.Before(p.ValidUntil) {
		return ErrPolicyExpired
	}
	seen := make(map[string]struct{}, len(p.Bindings))
	for _, binding := range p.Bindings {
		if binding.DatasetID == "" || binding.MirrorID == "" || binding.BindingRevision == "" || binding.DataVersion == "" ||
			binding.SchemaName == "" || binding.TableName == "" || binding.Prefix == "" {
			return fmt.Errorf("%w: incomplete relation binding", ErrAccessDenied)
		}
		key := binding.SchemaName + "\x00" + binding.TableName
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate relation %q", ErrAccessDenied, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (p RelationPolicy) Validate() error { return p.validate(time.Now()) }

func (p RelationPolicy) schemas() []string {
	seen := make(map[string]struct{}, len(p.Bindings))
	for _, binding := range p.Bindings {
		seen[binding.SchemaName] = struct{}{}
	}
	result := stringsFromSet(seen)
	sort.Strings(result)
	return result
}

func (p RelationPolicy) Schemas() []string { return p.schemas() }

// MirrorBindingVerifier is the production verifier for dataset-policy queries.
// It runs on the guarded query connection so the mirror version and prefix
// cannot change between validation and execution. The gateway supplies these
// values from the trusted dataset registry; clients never choose them.
func MirrorBindingVerifier(ctx context.Context, conn driver.Conn, policy RelationPolicy) error {
	for _, binding := range policy.Bindings {
		version, err := strconv.ParseInt(binding.DataVersion, 10, 64)
		if err != nil || version < 0 {
			return fmt.Errorf("%w: invalid mirror version for dataset %s", ErrAccessDenied, binding.DatasetID)
		}
		value, err := scalarOn(ctx, conn, `
			SELECT count(*)::BIGINT
			FROM bqsync_internal.mirror_state
			WHERE import_id = ? AND version = ? AND prefix = ?`,
			driver.NamedValue{Ordinal: 1, Value: binding.MirrorID},
			driver.NamedValue{Ordinal: 2, Value: version},
			driver.NamedValue{Ordinal: 3, Value: binding.Prefix},
		)
		if err != nil {
			return fmt.Errorf("%w: mirror binding lookup for dataset %s: %v", ErrAccessDenied, binding.DatasetID, err)
		}
		count, ok := value.(int64)
		if !ok || count != 1 {
			return fmt.Errorf("%w: mirror binding is no longer current for dataset %s", ErrAccessDenied, binding.DatasetID)
		}
		if err := verifyMirrorViewOn(ctx, conn, binding); err != nil {
			return err
		}
	}
	return nil
}

// verifyMirrorViewOn binds the authorized target relation to the exact
// version-scoped Parquet prefix recorded in the policy. mirror_state alone is
// insufficient: a stale catalog view can still point at another live mirror
// while the expected mirror row remains current. Reading duckdb_views and
// parsing the stored body on the guarded connection closes that catalog-swap
// race without trusting client SQL or path text.
func verifyMirrorViewOn(ctx context.Context, conn driver.Conn, binding AuthorizedRelation) error {
	value, err := scalarOn(ctx, conn, `
		SELECT CASE WHEN count(*) = 1 THEN max(sql) END
		FROM system.main.duckdb_views()
		WHERE database_name = system.main.current_database()
		  AND internal = false
		  AND schema_name = ? AND view_name = ?`,
		driver.NamedValue{Ordinal: 1, Value: binding.SchemaName},
		driver.NamedValue{Ordinal: 2, Value: binding.TableName})
	if err != nil {
		return fmt.Errorf("%w: target relation lookup failed for dataset %s: %v", ErrAccessDenied, binding.DatasetID, err)
	}
	stored, ok := value.(string)
	if !ok || stored == "" {
		return fmt.Errorf("%w: target relation %s.%s is not a platform-authored view", ErrAccessDenied, binding.SchemaName, binding.TableName)
	}
	body, err := viewBodyFromStoredSQL(stored)
	if err != nil {
		return fmt.Errorf("%w: target relation %s.%s has an invalid view definition: %v", ErrAccessDenied, binding.SchemaName, binding.TableName, err)
	}
	validator := &relationPrefixValidator{expected: strings.TrimRight(binding.Prefix, "/") + "/*.parquet"}
	if err := validateSQLOn(ctx, conn, body, validator); err != nil {
		return fmt.Errorf("%w: target relation %s.%s could not be validated: %v", ErrAccessDenied, binding.SchemaName, binding.TableName, err)
	}
	if validator.seen != 1 {
		return fmt.Errorf("%w: target relation %s.%s must read exactly one authorized mirror prefix", ErrAccessDenied, binding.SchemaName, binding.TableName)
	}
	return nil
}

type relationPrefixValidator struct {
	expected string
	seen     int
	errs     []error
}

func (v *relationPrefixValidator) CheckNode(node map[string]any, _ []string) {
	if node["type"] != "TABLE_FUNCTION" {
		return
	}
	function, ok := node["function"].(map[string]any)
	if !ok {
		return
	}
	name, _ := function["function_name"].(string)
	pathArguments, ok := remoteread.Lookup(strings.ToLower(name))
	if !ok {
		return
	}
	children, ok := function["children"].([]any)
	if !ok {
		return
	}
	positional := 0
	for _, child := range children {
		argument, ok := child.(map[string]any)
		if !ok {
			continue
		}
		if alias, named := argument["alias"].(string); named && alias != "" {
			if slices.Contains(pathArguments.Named, strings.ToLower(alias)) {
				v.checkPath(argument, name)
			}
			continue
		}
		if slices.Contains(pathArguments.Positional, positional) {
			v.checkPath(argument, name)
		}
		positional++
	}
}

func (v *relationPrefixValidator) checkPath(argument map[string]any, functionName string) {
	literal, ok := constantStringLiteral(argument)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("%w: path argument to '%s' is not a single constant literal", ErrAccessDenied, functionName))
		return
	}
	v.seen++
	if literal != v.expected {
		v.errs = append(v.errs, fmt.Errorf("%w: path argument to '%s' is not the authorized mirror prefix", ErrAccessDenied, functionName))
	}
}

func (v *relationPrefixValidator) Validate() []error { return append([]error(nil), v.errs...) }

func stringsFromSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

type relationPolicyValidator struct {
	allowed map[tableRef]struct{}
	refs    map[tableRef]struct{}
	ctes    map[string]struct{}
	errs    []error
}

func newRelationPolicyValidator(bindings []AuthorizedRelation) Validator {
	allowed := make(map[tableRef]struct{}, len(bindings))
	for _, binding := range bindings {
		allowed[tableRef{SchemaName: binding.SchemaName, TableName: binding.TableName}] = struct{}{}
	}
	return &relationPolicyValidator{allowed: allowed, refs: make(map[tableRef]struct{}), ctes: make(map[string]struct{})}
}

func (v *relationPolicyValidator) CheckNode(node map[string]any, keyStack []string) {
	if len(keyStack) >= 2 && keyStack[len(keyStack)-2] == "cte_map" && keyStack[len(keyStack)-1] == "map" {
		if key, ok := node["key"].(string); ok {
			v.ctes[key] = struct{}{}
		}
	}
	if node["type"] == "BASE_TABLE" {
		schema, _ := node["schema_name"].(string)
		table, _ := node["table_name"].(string)
		v.refs[tableRef{SchemaName: strings.TrimPrefix(schema, "schema_name:"), TableName: table}] = struct{}{}
	} else if node["type"] == "SHOW_REF" {
		if _, nested := node["query"]; !nested {
			v.errs = append(v.errs, fmt.Errorf("%w: catalog metadata statements are not permitted by a relation policy", ErrAccessDenied))
		}
	}
}

func (v *relationPolicyValidator) Validate() []error {
	errs := append([]error(nil), v.errs...)
	for ref := range v.refs {
		if ref.SchemaName == "" {
			if _, ok := v.ctes[ref.TableName]; ok {
				continue
			}
			errs = append(errs, fmt.Errorf("%w: relation '%s' must be schema-qualified", ErrAccessDenied, ref.TableName))
			continue
		}
		if _, ok := v.allowed[ref]; !ok {
			errs = append(errs, fmt.Errorf("%w: relation '%s.%s' is not in the authorization policy", ErrAccessDenied, ref.SchemaName, ref.TableName))
		}
	}
	return errs
}

func (db *DB) newPolicyValidators(policy RelationPolicy) []Validator {
	validators := db.newValidators(policy.schemas())
	return append(validators, newRelationPolicyValidator(policy.Bindings))
}

func (db *DB) validatePolicy(ctx context.Context, statement string, policy RelationPolicy) error {
	if err := policy.validate(time.Now()); err != nil {
		return err
	}
	if err := db.ValidateSQL(ctx, statement, db.newPolicyValidators(policy)...); err != nil {
		return fmt.Errorf("query: validation failed: %w", err)
	}
	return nil
}

func (db *DB) validatePolicyOn(ctx context.Context, conn driver.Conn, statement string, policy RelationPolicy) ([]tableRef, error) {
	validators := db.newPolicyValidators(policy)
	collector := newRelationCollector()
	validators = append(validators, collector)
	if err := validateSQLOn(ctx, conn, statement, validators...); err != nil {
		return nil, fmt.Errorf("query: validation failed: %w", err)
	}
	return collector.list(), nil
}

func (db *DB) QueryJSONWithPolicy(ctx context.Context, statement string, policy RelationPolicy) ([]byte, bool, error) {
	if err := policy.validate(time.Now()); err != nil {
		return nil, false, err
	}
	if db.transaction == nil || db.transaction.BindingVerifier == nil {
		return nil, false, fmt.Errorf("%w: relation policy requires the guarded transaction and binding verifier", ErrAccessDenied)
	}
	data, err := db.executeGuarded(ctx, statement, policy.schemas(), responseJSON, policy)
	return data, false, err
}

func (db *DB) QueryArrowWithPolicy(ctx context.Context, statement string, policy RelationPolicy) ([]byte, bool, error) {
	if err := policy.validate(time.Now()); err != nil {
		return nil, false, err
	}
	if db.transaction == nil || db.transaction.BindingVerifier == nil {
		return nil, false, fmt.Errorf("%w: relation policy requires the guarded transaction and binding verifier", ErrAccessDenied)
	}
	data, err := db.executeGuarded(ctx, statement, policy.schemas(), responseArrow, policy)
	return data, false, err
}
