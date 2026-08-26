# duckdb-server-go — fork development contract

This package is a **fork** of `uwdata/mosaic`'s `duckdb-server-go`, hardened for
use as the Yubico platform data plane. Everything outside this directory is
upstream and must stay that way.

You are reading this because you are about to change code here. Read it fully
before your first edit. It is normative, not advisory.

## The one thing to understand

We merge upstream regularly. **Every line we change inside a file upstream also
owns is a line we pay for again at every sync, forever.** Fork-owned files cost
nothing.

So the goal is not "write good code here". It is "write good code that lives
somewhere upstream will never touch". A 400-line new file is cheaper than a
five-line edit inside `query.go`.

The number we drive down is the **count of carried modifications**, tracked in
[`fork-inventory.json`](fork-inventory.json). Not lines, not files — modifications.
Today it is 54. Every one is a liability with a recurring cost.

## Rules

### 1. Stay inside this directory

All fork divergence lives under `packages/server/duckdb-server-go/`. Nothing
outside it may differ from upstream, with one carve-out: CI configuration under
`.github/workflows/`, because the checks below cannot run otherwise. That
carve-out is listed in `root_allowlist` and is the only one.

Do not add a fork note to the repo-root `AGENTS.md` or `README.md`. That would
itself be a violation.

### 2. Prefer adding over replacing

Adding beside upstream code is always preferred to changing or deleting it.

- Upstream code must not run? Disable it at the call site. Don't delete it.
- Upstream state needs replacing? Leave upstream's construction alone and put
  the replacement on a fork-owned type.
- Upstream function needs different behaviour? Wrap or decorate it. Don't edit
  its body.

Why this specific emphasis: `pkg/query/query.go` is +167/**-89** against
upstream. Those 89 *deleted* lines, not the 167 added ones, are what make it the
most expensive file in the fork to merge. A purely additive diff merges cleanly
almost regardless of size; a deleted hunk conflicts with any upstream change
that touches it.

Non-additive changes are permitted where genuinely correct. They need an
inventory entry saying why the additive form was rejected. Per-file deletion
counts are ratcheted in CI: they may fall freely, and may rise only alongside a
new or amended entry.

### 3. New logic goes in a new file

Default to creating a fork-owned file. Upstream files get hook points only.

Files listed in `fork_owned` carry no markers and no deletion count — they are
free. Adding one is always the right instinct.

The exemplar is in this package: `pkg/server/schema_resolver.go` is 41 lines of
fork logic behind **one** marker in `options.go`, because `pkg/server` gained a
hook rather than an implementation. Copy that shape.

### 4. A hook is one statement

A marked site should be a single statement or declaration. If your edit inside
an upstream file has a *body*, the body is in the wrong file.

Named exceptions live in the inventory. `execCommand`'s exec-denial gate is the
current legitimate one: a four-line guard whose entire purpose is to return
before upstream's code runs.

### 5. Upstream the seam, not the feature

The only change that removes a modification permanently instead of relocating
it.

Maintainers who would reject your feature will often accept a clean extension
point. If you find yourself editing an upstream file because there's nowhere to
plug in, the highest-value move is a PR to uwdata adding the plug — then your
implementation lives entirely in fork-owned files.

This applies to bug fixes too. If you fix a genuine upstream defect here, mark
it `upstream:candidate` so it can be sent home rather than carried forever.

### 6. Sync every upstream release, by merge

Not by rebase. `fork/main` is published and rebasing rewrites shared history; a
merge also resolves each conflict once instead of once per fork commit, and
preserves `// FORK:` blame.

See the runbook at the bottom.

### 7. Find out early

`git rerere` is enabled in this repo — leave it on. A nightly CI job trial-merges
upstream `main` and reports conflicts without blocking, so a conflict surfaces
the day upstream creates it rather than a hundred commits later.

## Marker syntax

Every edit inside an upstream file carries a marker:

```go
// FORK[<slug>]: <why this must live in an upstream file>
// FORK[<slug>] upstream:<status>: <why>
```

`<slug>` is short, kebab-case, unique in the package, and must have a matching
row in `fork-inventory.json`. The rationale answers *why it couldn't be
fork-owned* — not what the code does, which the code already says.

| `upstream:` | Meaning |
|---|---|
| omitted | local policy only, not an upstream candidate |
| `candidate` | should be proposed upstream; nobody has yet |
| `submitted:<url>` | PR open against uwdata/mosaic |
| `rejected` | upstream declined; carried, reason in the comment |

### The gofmt trap

**Inside an aligned block — struct fields, const blocks, import groups — put the
marker at end of line, never on its own line above.**

A standalone comment splits gofmt's alignment group and silently reformats the
untouched lines around it. Four of `pkg/server/server.go`'s 18 current deletions
are exactly this: adding `schemaResolver` with a comment above it rewrote
`logger`, `authorizer`, `httpHandler` and `websocketOptions`, none of which
anyone meant to touch.

```go
// wrong — reformats its neighbours
type handler struct {
    schemaMatchHeaders []string
    // FORK[handler-schema-resolver-field]: ...
    schemaResolver SchemaResolver
    logger         *slog.Logger
}

// right
type handler struct {
    schemaMatchHeaders []string
    schemaResolver     SchemaResolver // FORK[handler-schema-resolver-field]: ...
    logger             *slog.Logger
}
```

## Before you open a PR

- [ ] Every new marker has a slug and a row in `fork-inventory.json`.
- [ ] Every removed marker had its row deleted.
- [ ] No new deletions in an upstream file without an inventory entry explaining
      why additive didn't work.
- [ ] Nothing changed outside this directory except `root_allowlist` entries.
- [ ] Markers inside aligned blocks are end-of-line.
- [ ] `go test ./... -race` green.
- [ ] `pkg/platformauth/regression_test.go` passes **unmodified**. If a security
      regression test needed editing, you changed behaviour — that is a defect in
      your change, not in the test.

Ask yourself the question the inventory exists to force: *could this have been a
fork-owned file?* If the honest answer is "probably, with more effort", do the
more effort.

## Sync runbook

1. `git fetch origin` (uwdata); pick the release tag to sync to.
2. Trial-merge on a throwaway branch; record conflicted files and hunks; abort.
3. Merge the tag into a sync branch off `fork/main`.
4. Resolve. Every resolution inside an upstream file still obeys rules 2 and 4 —
   **a conflict is not a licence to inline.**
5. Full suite green including `-race`; `regression_test.go` unmodified.
6. Regenerate `fork-inventory.json`; advance `upstream_base`; delete entries
   upstream has absorbed.
7. Tag `fork/upstream-base-<release>`.
8. PR into `fork/main`.

## What the fork actually does

Context, so you can tell hardening from incidental change. The fork turns
upstream's server into a platform data plane with:

- Platform-session JWT validation, with schemas derived from the validated token
  rather than request headers (`pkg/platformauth`, `pkg/server/schema_resolver.go`).
- A transactional catalog guard: validation as the first statement after `BEGIN`,
  live catalog authorization, byte-capped materialization, commit before any byte
  reaches the client (`pkg/query/transaction.go`).
- Three independent gates denying `exec`.
- An external-access latch and Quack bootstrap for mirror deployments.

None of that may be weakened to satisfy a rule in this document. If a rule and
the hardening conflict, the hardening wins and the exception goes in the
inventory.
