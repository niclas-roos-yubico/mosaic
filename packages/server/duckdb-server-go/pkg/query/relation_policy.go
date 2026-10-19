package query

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var ErrPolicyExpired = errors.New("query: authorization policy expired")

// AuthorizedRelation is the trusted relation binding issued by the platform
// authorizer. BindingRevision and DataVersion are opaque to Mosaic; the
// configured verifier checks them against the mirror catalog on the guarded
// connection before execution.
type AuthorizedRelation struct {
	DatasetID       string
	BindingRevision string
	DataVersion     string
	SchemaName      string
	TableName       string
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
		if binding.DatasetID == "" || binding.BindingRevision == "" || binding.DataVersion == "" ||
			binding.SchemaName == "" || binding.TableName == "" {
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
	if db.transaction != nil {
		data, err := db.executeGuarded(ctx, statement, policy.schemas(), responseJSON, policy)
		return data, false, err
	}
	policyCtx, cancel := context.WithDeadline(ctx, policy.ValidUntil)
	defer cancel()
	if err := db.validatePolicy(policyCtx, statement, policy); err != nil {
		return nil, false, err
	}
	var buf []byte
	var builder strings.Builder
	if err := db.writeJSON(policyCtx, statement, &builder); err != nil {
		return nil, false, err
	}
	buf = []byte(builder.String())
	if !time.Now().Before(policy.ValidUntil) {
		return nil, false, ErrPolicyExpired
	}
	return buf, false, nil
}

func (db *DB) QueryArrowWithPolicy(ctx context.Context, statement string, policy RelationPolicy) ([]byte, bool, error) {
	if err := policy.validate(time.Now()); err != nil {
		return nil, false, err
	}
	if db.transaction != nil {
		data, err := db.executeGuarded(ctx, statement, policy.schemas(), responseArrow, policy)
		return data, false, err
	}
	policyCtx, cancel := context.WithDeadline(ctx, policy.ValidUntil)
	defer cancel()
	if err := db.validatePolicy(policyCtx, statement, policy); err != nil {
		return nil, false, err
	}
	var builder strings.Builder
	if err := db.writeArrow(policyCtx, statement, &builder); err != nil {
		return nil, false, err
	}
	if !time.Now().Before(policy.ValidUntil) {
		return nil, false, ErrPolicyExpired
	}
	return []byte(builder.String()), false, nil
}
