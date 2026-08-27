package query

// FORK-OWNED FILE. Scope-aware CTE resolution for the empty-schema base-table check.
//
// Why this exists (kata platform#8k4b). baseTableValidator lets an empty-schema BASE_TABLE through whenever
// SOME cte_map key anywhere in the statement matches its name -- see the IsCTE lookup in Validate. That test is
// scope-blind twice over: CheckNode registers every cte_map key it walks past regardless of where the CTE sits,
// and the map it registers into is shared across every statement in the batch. So declaring a CTE named exactly
// after the target, somewhere the binder will NOT resolve the target to it, exempts the target. The CTE never
// has to be referenced; it only has to exist. That bought reads of tables outside allowed_schemas, and -- since
// a bare path in FROM parses as a BASE_TABLE whose table_name is the path -- arbitrary local file reads once
// external access is on. Reproduced on fork/main e7479720.
//
// This validator runs ALONGSIDE baseTableValidator and only ever adds errors. validateParsedAST joins every
// validator's errors and any error denies, so the composite permits only what both permit: nothing here can
// weaken upstream's check, and no future upstream change to the exemption can weaken this one. Keeping them
// separate is AGENTS.md rule 4 -- two independent gates, not one tidier expression.
//
// Scoping rules below were measured against DuckDB, not read off the grammar. The three that matter, each of
// which binds to the REAL table and would otherwise still be exploitable:
//
//	WITH b AS (SELECT * FROM t), t AS (SELECT 1) SELECT * FROM b   -- forward reference in one WITH
//	WITH t AS (SELECT * FROM t) SELECT * FROM t                    -- non-recursive self reference
//	SELECT * FROM (WITH t AS (SELECT 1) SELECT 1) a, t b           -- inner declaration, outer reference
//
// and the two that must keep resolving to the CTE: an outer CTE is visible inside any nested subquery, and a
// RECURSIVE item is visible inside its own body.

import (
	"errors"
	"fmt"
	"maps"
	"strings"
)

// cteScopeValidator rejects an empty-schema BASE_TABLE unless a CTE of that name is in scope AT THAT REFERENCE.
type cteScopeValidator struct {
	sawNode  bool
	analyzed bool
	reported map[string]struct{}
	errs     []error
}

func newCTEScopeValidator() Validator {
	return &cteScopeValidator{reported: make(map[string]struct{})}
}

// CheckNode ignores everything except the statement root. Scope is a property of the path from the root, which
// the push-based Validator interface cannot express -- keyStack carries no array indices, so two sibling
// subqueries are indistinguishable by it -- so the analysis re-walks the statement itself. walkAST enters each
// statement with an empty keyStack and appends a key on every descent, which is what identifies the root.
// Re-walking per root is also what stops one statement in a batch from exempting the next: scope starts empty
// every time, and nothing is carried between statements except the errors already found.
func (v *cteScopeValidator) CheckNode(node map[string]any, keyStack []string) {
	v.sawNode = true
	if len(keyStack) != 0 {
		return
	}
	v.analyzed = true
	v.walkNode(node, map[string]struct{}{})
}

func (v *cteScopeValidator) Validate() []error {
	// Fail closed. This validator hangs off one property of upstream's walk (the empty keyStack at a statement
	// root). If a merge changes that, CheckNode stops recognising the root, the analysis silently never runs,
	// and platform#8k4b is back with the whole suite still green -- the exact shape of failure AGENTS.md rule 4
	// says not to accept. Denying every query instead makes it impossible to miss.
	if v.sawNode && !v.analyzed {
		return []error{errors.New(
			"query: CTE scope analysis did not run: the AST walk no longer enters statements at an empty keyStack")}
	}
	return v.errs
}

func (v *cteScopeValidator) walkNode(node map[string]any, scope map[string]struct{}) {
	visible := scope

	// A WITH item's body sees only the items declared BEFORE it, so the map is built up entry by entry rather
	// than collected first and applied to everything.
	entries, hasCTEMap := cteMapEntries(node)
	if hasCTEMap {
		visible = cloneScope(scope)
		for _, entry := range entries {
			for _, field := range entry {
				v.walkValue(field, visible)
			}
			if key, ok := entry["key"].(string); ok && key != "" {
				visible[key] = struct{}{}
			}
		}
	}

	// A materialized or recursive WITH item is re-emitted as a CTE_NODE / RECURSIVE_CTE_NODE carrying cte_name,
	// with its own body under "query" and the rest of the statement under "child". Only the recursive form may
	// reference itself; the materialized form is a binder error, so its body does not get its own name.
	bodyScope := visible
	if name, ok := node["cte_name"].(string); ok && name != "" {
		if node["type"] == "RECURSIVE_CTE_NODE" {
			visible = withCTE(visible, name)
			bodyScope = visible
		} else {
			bodyScope = withoutCTE(visible, name)
		}
	}

	v.checkBaseTable(node, visible)

	for key, val := range node {
		switch key {
		case "cte_map":
			if hasCTEMap {
				continue // already walked above, with the per-entry scope
			}
			// Shape we do not recognise: fall through and walk it with no CTE registered, so unrecognised
			// serialization denies bare references rather than exempting them.
			v.walkValue(val, visible)
		case "query":
			v.walkValue(val, bodyScope)
		default:
			v.walkValue(val, visible)
		}
	}
}

func (v *cteScopeValidator) walkValue(val any, scope map[string]struct{}) {
	switch typed := val.(type) {
	case map[string]any:
		v.walkNode(typed, scope)
	case []any:
		for _, item := range typed {
			v.walkValue(item, scope)
		}
	}
}

func (v *cteScopeValidator) checkBaseTable(node map[string]any, visible map[string]struct{}) {
	if node["type"] != "BASE_TABLE" {
		return
	}
	schemaName, _ := node["schema_name"].(string)
	if strings.TrimPrefix(schemaName, "schema_name:") != "" {
		return // a qualified reference cannot resolve to a CTE; baseTableValidator's schema check owns it
	}
	tableName, ok := node["table_name"].(string)
	if !ok || tableName == "" {
		return // malformed node; baseTableValidator reports the type error
	}
	if _, inScope := visible[tableName]; inScope {
		return
	}
	if _, already := v.reported[tableName]; already {
		return // one denial per table: DuckDB re-emits a materialized CTE's subtree more than once
	}
	v.reported[tableName] = struct{}{}
	v.errs = append(v.errs, fmt.Errorf(
		"%w: unauthorized access to table '%s' with empty schema: no CTE of that name is in scope at this reference",
		ErrAccessDenied, tableName))
}

// cteMapEntries returns the WITH items declared on node, in declaration order, and reports whether node carried
// a cte_map in the shape this file understands.
func cteMapEntries(node map[string]any) ([]map[string]any, bool) {
	cteMap, ok := node["cte_map"].(map[string]any)
	if !ok {
		return nil, false
	}
	raw, ok := cteMap["map"].([]any)
	if !ok {
		return nil, false
	}
	entries := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

func cloneScope(scope map[string]struct{}) map[string]struct{} {
	next := maps.Clone(scope)
	if next == nil {
		next = make(map[string]struct{})
	}
	return next
}

func withCTE(scope map[string]struct{}, name string) map[string]struct{} {
	if _, ok := scope[name]; ok {
		return scope
	}
	next := cloneScope(scope)
	next[name] = struct{}{}
	return next
}

func withoutCTE(scope map[string]struct{}, name string) map[string]struct{} {
	if _, ok := scope[name]; !ok {
		return scope
	}
	next := cloneScope(scope)
	delete(next, name)
	return next
}
