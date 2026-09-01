package query

// FORK-OWNED FILE. Two-tier validation: the narrower permission set a VIEW body is validated under, so a mirror
// can be served from object-store Parquet instead of a table landed on local disk (kata platform#34tp).
//
// Why two tiers. checkCatalogOn refuses anything that is not a BASE TABLE because a NAME must not resolve to
// something with a hidden body: the AST validators approve `analytics.mirror` on its schema name alone and never
// see what it expands to. That refusal is correct and platform#d5x9 confirmed it fires. Simply admitting VIEW is
// therefore a real vulnerability, not a relaxation -- a view in a schema the caller may read, whose body reads a
// private mirror's Parquet, would be served with no refusal anywhere.
//
// So the user's query keeps today's rules exactly, and a view body gets its own, narrower set:
//
//   - file reads are PERMITTED, but only for literal paths under MirrorFileRoot, and only through the two
//     Parquet readers. Every other file-reading function stays off the body's allowlist.
//   - schema references stay bounded by the CALLER's allowed_schemas, so a body cannot reach a schema the caller
//     could not have named itself.
//   - the body's own references are run back through the same catalog check, bounded by maxViewDepth.
//
// The admission and the body check are ONE function on purpose (checkRelationsOn below). AGENTS.md rule 4 warns
// against merging two security concerns into one call site; this is the opposite case. Admitting VIEW is only
// safe BECAUSE the body is validated, so there must be no path that does the first without the second. Splitting
// them into `checkCatalogOn` plus a separate `checkViewBodies` would leave a fail-open one deleted call away.
//
// Fail-closed by default: MirrorFileRoot is empty unless an operator sets --mirror-file-root, and an empty root
// refuses every VIEW with the message this package has always returned. The change is inert until opted into.
//
// KNOWN CEILINGS, deliberate and reviewed:
//
//   - A path argument must be exactly ONE constant string literal. A list, a concatenation, or any computed
//     expression is refused rather than inspected -- scanning a computed expression for constants is what lets
//     `read_parquet('gs://root/' || $evil)` through, and mirrors do not need it.
//   - MirrorFileRoot bounds reads to the mirror tree as a whole. It does NOT distinguish a private mirror's
//     Parquet from a public one, so a view in a public schema whose body names a private mirror's file is
//     admitted. What prevents that is that every view is platform-authored on the privileged quack channel --
//     recorded as INV-bqsync-no-user-created-views in the data-platform invariants doc, because under this change
//     it stops being incidental and becomes load-bearing.
//   - Symlinks and percent-encoding are not resolved. The `..` rejection covers the local-filesystem case that
//     motivates it; object stores do not interpret either.

import (
	"context"
	"database/sql/driver"
	"fmt"
	"slices"
	"strings"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/functionset/remoteread"
)

// maxViewDepth bounds recursion, not nesting. It caps how deep a single UNASSISTED chain of view-inside-view
// expansion may go: the user's query is depth 0, so 4 permits a mirror view over a staging view over a partition
// view and refuses anything deeper. Cycles cannot be created in DuckDB, but the bound holds regardless.
//
// It is deliberately NOT a ceiling on how many views one query may reach. `visited` is shared across the whole
// check, so naming the intermediate views alongside the deep one resolves each at depth 0 and the chain
// completes. That is fine and is the point: every view in it is still fully validated, exactly once. What the
// bound exists to stop is unbounded work and unbounded stack from a single reference, not a query that spells
// its own chain out.
const maxViewDepth = 4

// mirrorReadFunctions are the only file-reading functions a view body may call, added to the caller's allowlist
// for the body and nowhere else. Mirrors are exported as Parquet (COPY ... FORMAT parquet), so this is the whole
// list; widening it is a security change, not a configuration one.
var mirrorReadFunctions = []string{"read_parquet", "parquet_scan"}

// checkRelationsOn authorizes every relation the caller's query referenced. A BASE TABLE passes as it always
// has; a VIEW passes only if its stored body survives the body validator set; anything else is refused.
//
// visited carries the refs already authorized on this call so a diamond -- two views over one third view -- is
// checked once rather than exponentially. depth counts view expansions, not references.
func (db *DB) checkRelationsOn(
	ctx context.Context,
	conn driver.Conn,
	refs []tableRef,
	allowedSchemas []string,
	depth int,
	visited map[tableRef]struct{},
) error {
	for _, ref := range refs {
		if _, seen := visited[ref]; seen {
			continue
		}
		visited[ref] = struct{}{}

		// DuckDB exposes information_schema relations as system views, not user-authored catalog objects.
		// The AST schema validator has already required information_schema in the caller's allowed schemas.
		if ref.SchemaName == "information_schema" {
			continue
		}

		value, err := scalarOn(ctx, conn, `
			SELECT coalesce(max(table_type), 'ABSENT')
			FROM system.information_schema.tables
			WHERE table_schema = ? AND table_name = ?`,
			driver.NamedValue{Ordinal: 1, Value: ref.SchemaName},
			driver.NamedValue{Ordinal: 2, Value: ref.TableName})
		if err != nil {
			return fmt.Errorf("query: catalog lookup failed: %w", err)
		}

		switch fmt.Sprint(value) {
		case "BASE TABLE":
			continue
		case "VIEW":
			if err := db.checkViewBodyOn(ctx, conn, ref, allowedSchemas, depth, visited); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: '%s.%s' is not a physical table", ErrAccessDenied, ref.SchemaName, ref.TableName)
		}
	}
	return nil
}

// checkViewBodyOn resolves ref's stored definition on the SAME connection and transaction the caller's query was
// validated on -- the anti-TOCTOU half of guarded execution: the body authorized here is the body the pinned
// snapshot will expand.
func (db *DB) checkViewBodyOn(
	ctx context.Context,
	conn driver.Conn,
	ref tableRef,
	allowedSchemas []string,
	depth int,
	visited map[tableRef]struct{},
) error {
	root := db.mirrorFileRoot()
	if root == "" {
		// Unconfigured is the shipped default and must behave exactly as it did before two-tier validation
		// existed, down to the message platform#d5x9 recorded.
		return fmt.Errorf("%w: '%s.%s' is not a physical table", ErrAccessDenied, ref.SchemaName, ref.TableName)
	}
	if depth >= maxViewDepth {
		return fmt.Errorf("%w: view '%s.%s' exceeds the maximum view nesting depth of %d",
			ErrAccessDenied, ref.SchemaName, ref.TableName, maxViewDepth)
	}

	// Exactly one non-internal view in the current database, or nothing. The fork does not enforce catalog
	// qualification (a known gap), so a name matching in two attached databases must fail closed rather than
	// have one of them picked arbitrarily.
	//
	// Three of the four filters below are UNREACHABLE defensive terms, and deliberately so. Given
	// database_name = current_database(), a schema-qualified view name is unique, so count(*) can only be 0 or
	// 1 and the CASE can never fire; internal views live in system schemas, which no caller's allowed_schemas
	// contains, so a ref never names one; and nothing on the guarded path ever ATTACHes, so a second catalog
	// cannot appear on a pooled connection in the first place. Security review flagged all three as surviving
	// mutation — correctly, and there is no test that could kill those mutations without first building a
	// configuration the server cannot reach. They stay because each one becomes load-bearing the moment
	// another is weakened, which is the case they exist for. Do not delete one because it is untested.
	value, err := scalarOn(ctx, conn, `
		SELECT CASE WHEN count(*) = 1 THEN max(sql) END
		FROM system.main.duckdb_views()
		WHERE database_name = system.main.current_database()
		  AND internal = false
		  AND schema_name = ? AND view_name = ?`,
		driver.NamedValue{Ordinal: 1, Value: ref.SchemaName},
		driver.NamedValue{Ordinal: 2, Value: ref.TableName})
	if err != nil {
		return fmt.Errorf("query: view definition lookup failed: %w", err)
	}
	stored, ok := value.(string)
	if !ok || stored == "" {
		return fmt.Errorf("%w: '%s.%s' has no single resolvable view definition",
			ErrAccessDenied, ref.SchemaName, ref.TableName)
	}

	body, err := viewBodyFromStoredSQL(stored)
	if err != nil {
		return fmt.Errorf("%w in '%s.%s'", err, ref.SchemaName, ref.TableName)
	}

	collector := newRelationCollector()
	validators := append(db.viewBodyValidators(allowedSchemas, root), collector)
	if err := validateSQLOn(ctx, conn, body, validators...); err != nil {
		return fmt.Errorf("%w: view '%s.%s' body rejected: %w", ErrAccessDenied, ref.SchemaName, ref.TableName, err)
	}

	return db.checkRelationsOn(ctx, conn, collector.list(), allowedSchemas, depth+1, visited)
}

// mirrorFileRoot returns the configured root with a trailing separator, or "" when unset. The separator matters:
// without it a root of "gs://bucket/mirror" would also admit "gs://bucket/mirror-public/x.parquet".
func (db *DB) mirrorFileRoot() string {
	if db.transaction == nil || db.transaction.MirrorFileRoot == "" {
		return ""
	}
	return strings.TrimSuffix(db.transaction.MirrorFileRoot, "/") + "/"
}

// validateMirrorFileRoot rejects a root that does not actually bound anything. The prefix check is only as good
// as the prefix, and several roots that look configured bound nothing at all:
//
//   - "/" or a bare scheme like "gs://" -- every path is under it;
//   - a glob such as "/srv/mirror*" -- mirrorFileRoot appends "/", giving "/srv/mirror*/", and DuckDB then
//     expands "/srv/mirror*/x.parquet" across every sibling directory while the literal still matches the
//     prefix. This is the sibling-prefix leak the trailing separator was added to close, reintroduced through
//     the root instead of through the comparison;
//   - a relative path -- what it resolves to depends on the serving process's working directory;
//   - "..", for the same reason it is refused in a path.
//
// Startup is the only place this can be caught. A root is operator input read once, so a shape check here costs
// nothing per query and a bad root is a boot failure rather than a boundary that silently admits everything.
func validateMirrorFileRoot(root string) error {
	if root == "" {
		return nil
	}
	if strings.ContainsAny(root, "*?[{") {
		return fmt.Errorf("query: mirror file root %q must not contain glob metacharacters", root)
	}
	if strings.Contains(root, "..") {
		return fmt.Errorf("query: mirror file root %q must not contain a parent-directory segment", root)
	}
	if strings.TrimSpace(root) != root {
		return fmt.Errorf("query: mirror file root %q must not have leading or trailing whitespace", root)
	}
	path := root
	if scheme := strings.Index(root, "://"); scheme >= 0 {
		// An object-store root needs a bucket AND at least one prefix component under it: "gs://bucket/" is
		// the whole bucket, which is not a bound worth having.
		authorityAndPath := root[scheme+len("://"):]
		slash := strings.Index(authorityAndPath, "/")
		if slash < 0 || strings.Trim(authorityAndPath[slash:], "/") == "" {
			return fmt.Errorf("query: mirror file root %q must name a prefix below the bucket", root)
		}
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("query: mirror file root %q must be absolute", root)
	}
	if strings.Trim(path, "/") == "" {
		return fmt.Errorf("query: mirror file root %q must not be the filesystem root", root)
	}
	return nil
}

// viewBodyValidators is the BODY tier. It is not derived from newValidators: the sets differ in both directions,
// so expressing one as a tweak of the other would let a change to the user's set silently change the body's.
//
// The function allowlist is applied unconditionally here, even though newValidators applies it only when
// configured, because a body that may read files must never be function-unrestricted. validateGuardedOptions
// refuses a MirrorFileRoot without a configured allowlist, so this is defence in depth rather than the boundary.
//
// remoteURILiteralValidator is absent because it would reject the very thing a mirror body exists to read: a
// gs:// literal. mirrorRootValidator replaces its PATH check and is narrower there -- it demands the literal be
// under the root rather than merely not be a remote URI, and it refuses computed path expressions the
// remote-URI scan walks past.
//
// It is NOT narrower overall, and an earlier revision of this comment claiming so was wrong. The remote-URI
// validator does a second, unrelated job: rejecting the nested SQL executors. Dropping it dropped that, and the
// function allowlist did not cover the gap -- `--function-allowlist=query` is a supported operator flag, and a
// body calling query('SELECT * FROM private_ns.salaries') was served across the caller's schema bound, because
// the nested string is never parsed and so no validator here ever sees it. nestedSQLValidator restores that
// check as its own gate rather than folding it into mirrorRootValidator: two concerns, two validators
// (AGENTS.md rule 4).
func (db *DB) viewBodyValidators(allowedSchemas []string, root string) []Validator {
	allowlist := append(append([]string(nil), db.functionAllowlist...), mirrorReadFunctions...)
	return []Validator{
		newBaseTableValidator(allowedSchemas),
		newCTEScopeValidator(),
		newMirrorRootValidator(root),
		newNestedSQLValidator(),
		newFunctionAllowlistValidator(allowlist),
	}
	// No function BLOCKLIST branch: New rejects an allowlist and a blocklist together, and
	// validateGuardedOptions requires an allowlist whenever a root is set, so a blocklist is unreachable in any
	// configuration that reaches this function. A branch that cannot run is not defence in depth, it is a
	// branch no test can cover.
}

// nestedSQLValidator refuses the executors that take SQL as a STRING. They are the one class the rest of this
// file cannot reason about: the nested statement is never parsed, so the schema bound, the mirror root and the
// recursion all see an opaque literal and pass it.
//
// The names come from remote_uri.go's own lists rather than being restated here, so a name added there is
// covered here without anyone remembering to.
type nestedSQLValidator struct{ errs []error }

func newNestedSQLValidator() Validator { return &nestedSQLValidator{} }

func (v *nestedSQLValidator) CheckNode(node map[string]any, _ []string) {
	var functionName string
	switch node["type"] {
	case "TABLE_FUNCTION":
		function, ok := node["function"].(map[string]any)
		if !ok {
			return // malformed; mirrorRootValidator reports the shape error
		}
		functionName, _ = function["function_name"].(string)
	default:
		if node["class"] != "FUNCTION" && node["class"] != "WINDOW" {
			return
		}
		functionName, _ = node["function_name"].(string)
	}
	functionName = strings.ToLower(functionName)
	if functionName == "" {
		return
	}
	// The scalar executor is matched by bare name only. remoteURILiteralValidator additionally inspects the
	// catalog/schema fields to avoid rejecting a same-named user function; here there is no such thing to
	// protect, because a user-defined function in the catalog already denies every query via the macro check.
	if slices.Contains(nestedSQLTableExecutors[:], functionName) || functionName == nestedSQLScalarExecutor {
		v.errs = append(v.errs, fmt.Errorf(
			"%w: nested SQL executor '%s' is not allowed in a view body", ErrAccessDenied, functionName))
	}
}

func (v *nestedSQLValidator) Validate() []error { return append([]error(nil), v.errs...) }

// mirrorRootValidator refuses any path argument to a file-reading function that is not a single constant string
// literal under root. It checks every function in the remote-read inventory, not just the two on the body's
// allowlist, so widening mirrorReadFunctions cannot accidentally widen this.
type mirrorRootValidator struct {
	root string
	errs []error
}

func newMirrorRootValidator(root string) Validator { return &mirrorRootValidator{root: root} }

func (v *mirrorRootValidator) CheckNode(node map[string]any, _ []string) {
	if node["type"] != "TABLE_FUNCTION" {
		return
	}
	function, ok := node["function"].(map[string]any)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("%w: malformed table function node in view body", ErrAccessDenied))
		return
	}
	functionName, ok := function["function_name"].(string)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf("%w: table function node with no name in view body", ErrAccessDenied))
		return
	}
	functionName = strings.ToLower(functionName)
	pathArguments, ok := remoteread.Lookup(functionName)
	if !ok {
		return // not a file reader; the body's function allowlist decides whether it may be called at all
	}
	children, ok := function["children"].([]any)
	if !ok {
		return // no arguments to check
	}

	positional := 0
	for _, child := range children {
		argument, ok := child.(map[string]any)
		if !ok {
			continue
		}
		if name, named := argument["alias"].(string); named && name != "" {
			if slices.Contains(pathArguments.Named, strings.ToLower(name)) {
				v.checkPath(argument, functionName)
			}
			continue
		}
		if slices.Contains(pathArguments.Positional, positional) {
			v.checkPath(argument, functionName)
		}
		positional++
	}
}

func (v *mirrorRootValidator) checkPath(argument map[string]any, functionName string) {
	literal, ok := constantStringLiteral(argument)
	if !ok {
		v.errs = append(v.errs, fmt.Errorf(
			"%w: the path argument to '%s' must be a single constant string literal", ErrAccessDenied, functionName))
		return
	}
	if strings.Contains(literal, "..") {
		v.errs = append(v.errs, fmt.Errorf(
			"%w: path argument to '%s' contains a parent-directory segment", ErrAccessDenied, functionName))
		return
	}
	if !strings.HasPrefix(literal, v.root) {
		v.errs = append(v.errs, fmt.Errorf(
			"%w: path argument to '%s' is outside the mirror file root", ErrAccessDenied, functionName))
	}
}

func (v *mirrorRootValidator) Validate() []error { return append([]error(nil), v.errs...) }

// constantStringLiteral reports the literal only when the whole expression IS one non-null string constant.
// Anything else -- a list, a cast, a concatenation, a column reference -- returns false, and the caller refuses.
func constantStringLiteral(expression map[string]any) (string, bool) {
	if expression["class"] != "CONSTANT" {
		return "", false
	}
	value, ok := expression["value"].(map[string]any)
	if !ok {
		return "", false
	}
	if isNull, _ := value["is_null"].(bool); isNull {
		return "", false
	}
	literal, ok := value["value"].(string)
	if !ok || literal == "" {
		return "", false
	}
	return literal, true
}

// viewBodyFromStoredSQL returns the SELECT half of a stored view definition.
//
// DuckDB stores views re-serialized into one canonical form -- `CREATE VIEW <name>[ (cols)] AS <body>;`, with
// OR REPLACE and TEMPORARY already normalized away -- so the split point is the first `AS` keyword outside any
// quoted identifier, string literal or parenthesised column list. Measured against DuckDB 1.5.5, including a
// view whose own name contains ` AS `.
//
// This is the one step that is textual rather than parsed, because json_serialize_sql refuses a CREATE statement
// ("Only SELECT statements can be serialized to json!"), so the body cannot be reached through the parser. It is
// verified rather than trusted: a wrong split yields text that does not parse as a SELECT, and the caller's
// validateSQLOn then fails closed. Splitting too LATE -- the dangerous direction, since it would validate less
// than the body -- cannot happen, because the separator precedes any `AS` the body could contain.
func viewBodyFromStoredSQL(stored string) (string, error) {
	trimmed := strings.TrimSpace(stored)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "CREATE VIEW ") {
		return "", fmt.Errorf("%w: stored view definition is not in the expected CREATE VIEW form", ErrAccessDenied)
	}
	index, ok := topLevelASIndex(trimmed)
	if !ok {
		return "", fmt.Errorf("%w: stored view definition has no top-level AS", ErrAccessDenied)
	}
	body := strings.TrimSpace(trimmed[index+len("AS"):])
	if body == "" {
		return "", fmt.Errorf("%w: stored view definition has an empty body", ErrAccessDenied)
	}
	return body, nil
}

// topLevelASIndex returns the offset of the first `AS` keyword that is not inside a string literal, a quoted
// identifier or parentheses. Both quote forms double to escape, which is how DuckDB re-serializes them.
func topLevelASIndex(s string) (int, bool) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
			j := i + 1
			for j < len(s) {
				if s[j] != c {
					j++
					continue
				}
				if j+1 < len(s) && s[j+1] == c {
					j += 2
					continue
				}
				break
			}
			if j >= len(s) {
				return 0, false // unterminated quote: refuse rather than guess where it ended
			}
			i = j
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth != 0 || !isSQLSpace(c) {
				continue
			}
			rest := s[i+1:]
			if len(rest) >= 3 && (rest[0] == 'A' || rest[0] == 'a') && (rest[1] == 'S' || rest[1] == 's') && isSQLSpace(rest[2]) {
				return i + 1, true
			}
		}
	}
	return 0, false
}

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
