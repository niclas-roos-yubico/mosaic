package query

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

var (
	ErrAccessDenied = errors.New("query: access denied")

	ErrUnsupportedStatement = errors.New("query: unsupported statement")
)

type Validator interface {
	// CheckNode is called once for each node in the AST
	// - node: the current node being processed
	// - keyStack: contains the stack of keys leading to this node, with the root being the first element,
	//   and the parent key being the last element
	//
	// This explicitly does not not return an error. Any errors found should be collected and returned
	// in the Validate() method.
	CheckNode(node map[string]any, keyStack []string)

	// Validate is called after the entire AST has been processed. It should return any errors found during
	// the CheckNode calls, or any additional validation errors that can only be determined after
	// processing the entire AST. This allows validators to collect state during the AST traversal and perform more
	// complex validation that may depend on multiple nodes or the overall structure of the AST.
	//
	// It returns a slice of errors, to encourage collecting all errors rather than stopping at the first one.
	// If no errors are found, it should return nil.
	Validate() []error
}

type ErrorDetails struct {
	Type     string `json:"error_type"`
	Subtype  string `json:"error_subtype"`
	Message  string `json:"error_message"`
	Position string `json:"position"`
}

func (e ErrorDetails) Error() string {
	details := "query"
	if e.Type != "" {
		details += ": " + e.Type
	}
	if e.Subtype != "" {
		details += " (" + e.Subtype + ")"
	}
	if e.Position != "" {
		details += " at " + e.Position
	}
	if e.Message != "" {
		details += ": " + e.Message
	}
	return details
}

func (e ErrorDetails) Is(target error) bool {
	return target == ErrUnsupportedStatement && strings.EqualFold(e.Type, "not implemented")
}

// ValidateSQL validates the given SQL query using the provided validators
// FORK: parses the AST via db.db.QueryRowContext (unchanged) but delegates AST validation to the extracted
// validateParsedAST, which is shared with the connection-pinned validateSQLOn below.
func (db *DB) ValidateSQL(ctx context.Context, sql string, validators ...Validator) error {
	// Qualify the built-in to prevent database macros from shadowing validation.
	serializeSQL := fmt.Sprintf("SELECT system.main.json_serialize_sql(%s, skip_default := true, skip_empty := true, skip_null := true) as ast", quoteLiteral(sql))

	var m map[string]any

	err := db.db.QueryRowContext(ctx, serializeSQL).Scan(&m)
	if err != nil {
		return fmt.Errorf("failed to parse SQL query: %w", err)
	}

	return validateParsedAST(m, validators...)
}

// FORK: validateParsedAST is the AST-validation half extracted from ValidateSQL's body, so that it can be reused by
// validateSQLOn, which parses the AST on a specific driver.Conn instead of through db.db.
func validateParsedAST(m map[string]any, validators ...Validator) error {
	parseError, ok := m["error"].(bool)
	if !ok {
		return errors.New("invalid SQL parser response: missing error status")
	}
	if parseError {
		return ErrorDetails{
			Type:     stringField(m, "error_type"),
			Subtype:  stringField(m, "error_subtype"),
			Message:  stringField(m, "error_message"),
			Position: stringField(m, "position"),
		}
	}

	statements, ok := m["statements"].([]any)
	if !ok {
		return errors.New("invalid SQL parser response: missing or invalid statements")
	}

	// Extract all schema references, including tables without an explicit schema reference, from the AST
	for _, statement := range statements {
		mapped, ok := statement.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid statement format: %v", statement)
		}

		walkAST(mapped, make([]string, 0, 10), validators)
	}

	var combined []error
	for _, validator := range validators {
		combined = append(combined, validator.Validate()...)
	}
	return errors.Join(combined...)
}

// FORK: new function. validateSQLOn parses and validates SQL on a specific driver.Conn (bypassing db.db), so that
// parsing participates in a transaction already open on conn.
func validateSQLOn(ctx context.Context, conn driver.Conn, submitted string, validators ...Validator) error {
	statement := fmt.Sprintf("SELECT system.main.json_serialize_sql(%s, skip_default := true, skip_empty := true, skip_null := true) AS ast", quoteLiteral(submitted))
	value, err := scalarOn(ctx, conn, statement)
	if err != nil {
		return fmt.Errorf("failed to parse SQL query: %w", err)
	}
	var parsed map[string]any
	switch value := value.(type) {
	case map[string]any:
		parsed = value
	case string:
		if err := json.Unmarshal([]byte(value), &parsed); err != nil {
			return fmt.Errorf("invalid SQL parser JSON: %w", err)
		}
	case []byte:
		if err := json.Unmarshal(value, &parsed); err != nil {
			return fmt.Errorf("invalid SQL parser JSON: %w", err)
		}
	default:
		return fmt.Errorf("invalid SQL parser response type %T", value)
	}
	return validateParsedAST(parsed, validators...)
}

// FORK: new type. relationCollector is a Validator that records every BASE_TABLE reference the AST walk visits, so
// callers of validateQueryOn can run a live catalog check (Task 6) against exactly the tables the query touches.
// It never rejects anything itself (Validate always returns nil); it only collects.
type relationCollector struct{ refs map[tableRef]struct{} }

func newRelationCollector() *relationCollector {
	return &relationCollector{refs: make(map[tableRef]struct{})}
}

func (v *relationCollector) CheckNode(node map[string]any, _ []string) {
	if node["type"] != "BASE_TABLE" {
		return
	}
	schema, _ := node["schema_name"].(string)
	name, _ := node["table_name"].(string)
	if schema != "" && name != "" {
		v.refs[tableRef{SchemaName: strings.TrimPrefix(schema, "schema_name:"), TableName: name}] = struct{}{}
	}
}

func (*relationCollector) Validate() []error { return nil }

// list returns the collected table references sorted deterministically by schema then table name, so downstream
// catalog checks (Task 6) and execution (Task 7) see a stable order.
func (v *relationCollector) list() []tableRef {
	refs := make([]tableRef, 0, len(v.refs))
	for ref := range v.refs {
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b tableRef) int {
		if n := strings.Compare(a.SchemaName, b.SchemaName); n != 0 {
			return n
		}
		return strings.Compare(a.TableName, b.TableName)
	})
	return refs
}

func stringField(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}

// quoteLiteral properly escapes a string for use as a SQL string literal
func quoteLiteral(s string) string {
	// Escape single quotes by doubling them
	escaped := strings.ReplaceAll(s, "'", "''")
	return "'" + escaped + "'"
}

func walkASTSlice(nodes []any, keyStack []string, validators []Validator) {
	for _, node := range nodes {
		switch typedNode := node.(type) {
		case map[string]any:
			walkAST(typedNode, keyStack, validators)

		case []any:
			walkASTSlice(typedNode, keyStack, validators)
		}
	}
}

func walkAST(node map[string]any, keyStack []string, validators []Validator) {
	for _, validator := range validators {
		validator.CheckNode(node, keyStack)
	}

	for key, val := range node {
		switch typedVal := val.(type) {
		case map[string]any:
			walkAST(typedVal, append(keyStack, key), validators)

		case []any:
			walkASTSlice(typedVal, append(keyStack, key), validators)
		}
	}
}

// baseTableValidator validates that the SQL query only accesses schemas that match request headers
type baseTableValidator struct {
	allowedSchemas []string
	baseTables     map[tableRef]struct{}
	errs           []error
}

type tableRef struct {
	SchemaName string `json:"schema_name"`
	TableName  string `json:"table_name"`
	IsCTE      bool   `json:"is_cte,omitempty"`
}

func newBaseTableValidator(allowedSchemas []string) Validator {
	return &baseTableValidator{
		allowedSchemas: allowedSchemas,
		baseTables:     make(map[tableRef]struct{}),
	}
}

func (v *baseTableValidator) CheckNode(node map[string]any, keyStack []string) {
	if class, exists := node["class"]; exists && (class == "FUNCTION" || class == "WINDOW") {
		v.rejectCatalogReference(node, "catalog")
	}

	val, exists := node["type"]
	if exists {
		switch val {
		case "BASE_TABLE":
			v.handleBaseTable(node)
		case "SHOW_REF":
			v.handleShowRef(node)
		}
	}

	if len(keyStack) >= 2 && keyStack[len(keyStack)-2] == "cte_map" && keyStack[len(keyStack)-1] == "map" {
		val, exists = node["key"]
		if exists {
			v.baseTables[tableRef{
				TableName: val.(string),
				IsCTE:     true,
			}] = struct{}{}
		}
	}
}

func (v *baseTableValidator) handleShowRef(showRef map[string]any) {
	if v.rejectCatalogReference(showRef, "catalog_name") {
		return
	}

	// DESCRIBE statements contain a nested query whose base tables are validated separately.
	if _, exists := showRef["query"]; exists {
		return
	}

	schemaName, exists := showRef["schema_name"]
	if !exists {
		v.errs = append(v.errs, fmt.Errorf("%w: SHOW statement requires an explicit authorized schema", ErrAccessDenied))
		return
	}

	schemaNameStr, ok := schemaName.(string)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("invalid 'schema_name' in show reference, expected string: %v", schemaName))
		return
	}
	schemaNameStr = strings.TrimPrefix(schemaNameStr, "schema_name:")
	if !slices.Contains(v.allowedSchemas, schemaNameStr) {
		v.errs = append(v.errs, fmt.Errorf("%w: unauthorized access to schema '%s'", ErrAccessDenied, schemaNameStr))
	}
}

func (v *baseTableValidator) handleBaseTable(baseTable map[string]any) {
	if v.rejectCatalogReference(baseTable, "catalog_name") {
		return
	}

	var schemaNameStr string
	schemaName, exists := baseTable["schema_name"]
	if exists {
		var ok bool
		schemaNameStr, ok = schemaName.(string)
		if !ok {
			v.errs = append(v.errs, fmt.Errorf("invalid 'schema_name' in from_table, expected string: %v", schemaName))
			return
		}
	}

	tableName := baseTable["table_name"]
	tableNameStr, ok := tableName.(string)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("invalid 'table_name' in from_table, expected string: %v", tableName))
		return
	}

	// purposefully include empty schemas. We can reject them later if needed
	v.baseTables[tableRef{
		SchemaName: strings.TrimPrefix(schemaNameStr, "schema_name:"),
		TableName:  tableNameStr,
	}] = struct{}{}
}

func (v *baseTableValidator) rejectCatalogReference(ref map[string]any, field string) bool {
	catalogName, exists := ref[field]
	if !exists {
		return false
	}

	catalogNameStr, ok := catalogName.(string)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("invalid '%s', expected string: %v", field, catalogName))
		return true
	}
	catalogNameStr = strings.TrimPrefix(catalogNameStr, field+":")
	v.errs = append(v.errs, fmt.Errorf("%w: access to catalog '%s' is not allowed", ErrAccessDenied, catalogNameStr))
	return true
}

func (v *baseTableValidator) Validate() []error {
	errs := append([]error(nil), v.errs...)

	// Check if all referenced schemas are allowed
	for baseTable := range v.baseTables {
		if baseTable.SchemaName == "" {
			_, ok := v.baseTables[tableRef{TableName: baseTable.TableName, IsCTE: true}]
			if ok {
				continue // empty schemas are allowed if they are CTEs
			}
			errs = append(errs, fmt.Errorf("%w: unauthorized access to table '%s' with empty schema", ErrAccessDenied, baseTable.TableName))
			continue
		}

		if !slices.Contains(v.allowedSchemas, baseTable.SchemaName) {
			errs = append(errs, fmt.Errorf("%w: unauthorized access to schema '%s'", ErrAccessDenied, baseTable.SchemaName))
		}
	}

	return errs
}

type functionListValidator struct {
	functions      []string
	allowlist      bool
	functionCounts map[string]int
	errs           []error
}

func newFunctionBlocklistValidator(blockedFunctions []string) Validator {
	return newFunctionListValidator(blockedFunctions, false)
}

func newFunctionAllowlistValidator(allowedFunctions []string) Validator {
	return newFunctionListValidator(allowedFunctions, true)
}

func newFunctionListValidator(functions []string, allowlist bool) Validator {
	return &functionListValidator{
		functions:      functions,
		allowlist:      allowlist,
		functionCounts: make(map[string]int),
	}
}

func (v *functionListValidator) CheckNode(node map[string]any, _ []string) {
	class, exists := node["class"]
	if !exists {
		return
	}
	if class != "FUNCTION" && class != "WINDOW" {
		return
	}

	functionName, exists := node["function_name"]
	if !exists {
		v.errs = append(v.errs, errors.New("query: invalid function node: missing 'function_name'"))
		return
	}

	functionNameStr, ok := functionName.(string)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("query: invalid 'function_name' in function, expected string: %v", functionName))
		return
	}
	functionNameStr = strings.ToLower(functionNameStr)
	v.functionCounts[functionNameStr]++
}

func (v *functionListValidator) Validate() []error {
	errs := append([]error(nil), v.errs...)
	for _, functionName := range slices.Sorted(maps.Keys(v.functionCounts)) {
		listed := slices.Contains(v.functions, functionName)
		if listed == v.allowlist {
			continue
		}

		var err error
		if v.allowlist {
			err = fmt.Errorf("%w: function '%s' is not in the allowlist", ErrAccessDenied, functionName)
		} else {
			err = fmt.Errorf("%w: use of function '%s' is not allowed", ErrAccessDenied, functionName)
		}
		if count := v.functionCounts[functionName]; count > 1 {
			err = fmt.Errorf("%w (%d occurrences)", err, count)
		}
		errs = append(errs, err)
	}
	return errs
}
