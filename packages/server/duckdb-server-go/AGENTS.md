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
Today it is 44. Every one is a liability with a recurring cost.

## Rules

### 0. None of this outranks the hardening

Every rule in this document exists to reduce **rebase cost**. Rebase cost never
justifies a weaker security posture. If a rule below and the hardening pull in
opposite directions, the hardening wins and the exception goes in the inventory
— that is a normal, expected outcome, not a failure to comply.

Be especially wary when a rule makes a security control *tidier*. Tidier is not
the goal; the goal is that the control cannot be bypassed. See rule 4.

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

Why this specific emphasis: `pkg/query/query.go` was +167/**-89** against
upstream when this document was written, which made it the most expensive file
in the fork to merge. Those 89 *deleted* lines, not the 167 added ones, were the
cost. A purely additive diff merges cleanly almost regardless of size; a deleted
hunk conflicts with any upstream change that touches it.

That thinning has since landed (`platform#z5x2` component 2). The lesson stands
— the deletion count is the number that matters — but this paragraph carries no
current figures on purpose: read them out of `fork-inventory.json`'s `deletions`
map, which is the only place they are kept up to date.

Non-additive changes are permitted where genuinely correct. They need an
inventory entry saying why the additive form was rejected. Per-file deletion
counts in `fork-inventory.json` are a ratchet: they may fall freely, and may
rise only alongside a new or amended entry. **Nothing enforces that ratchet
automatically yet** — it is reviewer-enforced, tracked as kata `platform#cbjc`.
Do not read the ratchet as a check that will catch you.

### 3. New logic goes in a new file

Default to creating a fork-owned file. Upstream files get hook points only.

Files listed in `fork_owned` carry no markers and no deletion count — they are
free. Adding one is always the right instinct.

The exemplar is in this package: `pkg/server/schema_resolver.go` is 41 lines of
fork logic behind **one** marker in `options.go`, because `pkg/server` gained a
hook rather than an implementation. Copy that shape.

The lever that makes this achievable in Go: **methods on a type compile from any
file in the package.** A method on upstream's `handler` or `DB` can live in a
fork-owned file with no upstream edit at all.

**That lever only pays for a whole new function. It does not pay for relocating
a body that already lives inside an upstream function.** Adjacency in the
upstream file is what keeps an extraction cheap: git scores an adjacent moved
body as context, so the extraction costs ~1 deletion (the signature line).
Move that same body out to a fork-owned file and the lines stop being adjacent
context — they become deletions. Measured: relocating `writeJSONOn` /
`writeArrowOn` out of `query.go` into a fork-owned `encoder.go` took
`query.go` from 77/7 to **47/67**, a cost of +60 deletions, for code that was
already free where it sat. The only way to get the deletion count *and* the
new file is to duplicate the body, and a duplicate is a second copy that a fix
lands on once and not the other.

So: **extract adjacently, in the upstream file. Relocate only whole new
functions to a fork-owned file.** This applies to component 3's planned moves
(`requestSchemas`, the WebSocket session lifecycle) as much as it did here —
check adjacency before moving a body out, not after.

**This applies to tests too.** A fork test living in an upstream `_test.go` file
is pure cost with no upside: test files are where upstream *appends* most freely,
so a fork test sitting at the bottom of one is sitting exactly where the next
upstream test will land. Put fork tests in a fork-owned `_foo_fork_test.go`. They
are in the same package, so nothing is lost — and unlike production hooks, a test
has no call site that must stay behind, so the move is always free.

### 4. A hook is one statement

A marked site should be a single statement or declaration. If your edit inside
an upstream file has a *body*, the body is in the wrong file.

Named exceptions live in the inventory. `execCommand`'s exec-denial gate is the
current legitimate one: a four-line guard whose entire purpose is to return
before upstream's code runs.

**Do not buy a shorter hook with a weaker guarantee.** Prefer a mechanism the
compiler enforces over one that depends on a caller remembering. An extra
parameter threaded through an upstream signature is checked at every call site
and cannot be omitted; a value smuggled through a `context.Context`, a field set
during setup, or a convention documented in a comment all fail *silently* when
some path skips them. In a security control — authorization, expiry, denial
gates — that silence is the whole problem.

So: a four-line guard the compiler protects beats a one-line hook it doesn't.
Retiring an exception in this list is not worth a fail-open. If you find yourself
merging two security concerns into one call site to satisfy this rule, that is
the signal to stop and take the exception instead.

**The same failure mode applies to types, not just hooks: a security guard must
never be expressed as a wrapper type over an upstream type.** Go has no virtual
dispatch. An embedded-struct decorator (`GuardedDB{ *DB }`) only intercepts calls
made *through* the wrapper; any call the upstream type makes to itself — including
a future upstream refactor that routes one entry point through another — reaches
the unguarded implementation with no compiler signal, no conflict, no failing
test. Worse than the dispatch gap: the upstream constructor keeps returning the
un-wrapped type, so every existing caller already holds an unguarded object
before the decorator is ever applied. A guard must be **state on the receiver**,
reached through every dispatch path including the constructor's — not a type
applied on top after construction. Measured: a decorator over `*query.DB` served
a cross-tenant row with an empty allowed-schema list, left `MaxResultBytes`
unenforced, and served a view the live catalog check exists to reject — while
`pkg/platformauth/regression_test.go` stayed green throughout, because that suite
exercises the guard through `server.New` rather than through the `*DB` the
decorator leaves unguarded. The four `if db.transaction != nil` preludes in
`pkg/query/query.go` are this rule's compliant form: state on the receiver,
unremovable by any dispatch path, each registered as its own rule-4 exception.

**State the target as a property, not a count.** "No marked site has a body, and
deletions in this file are at or below N" is the bar. A raw marker count invites
exactly the wrong optimisation — merging unrelated hooks to make one number
smaller, which is how you arrive at a tidier, weaker design. Two adjacent
one-line hooks are cheaper to rebase than one clever hook that carries two
concerns.

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

Two mechanisms. **Neither is set up yet** — this section describes the intended
state, and says so rather than pretending.

**`git rerere`** reuses recorded conflict resolutions, turning repeated
resolution across overlapping regions into a one-time cost. It is **not**
currently enabled — `git config rerere.enabled` returns empty, locally and
globally. Turn it on before the next sync:

```sh
git config rerere.enabled true
```

Until it is on, the `-c rerere.enabled=false` guard in the runbook below is a
no-op. That guard is still correct to write, because it must not become a
silent no-op *after* rerere is enabled.

**A nightly trial-merge CI job** against upstream `main`, reporting conflicts
without blocking, so a conflict surfaces the day upstream creates it rather than
a hundred commits later. Not built yet either.

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
- [ ] No fork test left sitting in an upstream test file — see below.
- [ ] Build and test **with the same build tag CI uses**, or you are not testing
      what CI tests (`.github/workflows/test.yml`):
      `go build -tags=duckdb_arrow ./...` and `go test -tags=duckdb_arrow -race ./...`
- [ ] `pkg/platformauth/regression_test.go` passes **unmodified**. If a security
      regression test needed editing, you changed behaviour — that is a defect in
      your change, not in the test.
- [ ] Every upstream file carrying fork markers has a source guard, in the shape
      `platform_test.go` uses for `main.go`: one test asserting every
      `// FORK[<slug>]` marker is still present, and a second test asserting a
      distinctive substring of the load-bearing code the marker sits next to.
      The marker assertion alone is not enough — some hooks carry their marker
      on its own line above the statement, so the statement can be deleted
      while the marker stays and the marker-only check still passes.

Ask yourself the question the inventory exists to force: *could this have been a
fork-owned file?* If the honest answer is "probably, with more effort", do the
more effort.

## Sync runbook

1. `git fetch origin` (uwdata); pick the release tag to sync to.
2. Trial-merge on a throwaway branch; record conflicted files and hunks; abort.
   **Measure with `git -c rerere.enabled=false merge ...`.** Once rerere is on
   (rule 7), a cached resolution makes a conflict vanish from the count without
   the underlying divergence having gone anywhere, silently understating every
   before/after measurement you take.

   **A zero-conflict result may prove nothing.** Check how often upstream
   actually touches the files you changed:
   `git log --oneline <upstream_base> -- <path> | wc -l`. As of v0.31.0 that is
   2 commits for `pkg/server/server.go`, 3 for `pkg/query/query.go`, 9 for
   `main.go` — so a clean merge in `pkg/server` is the expected outcome whether
   or not the thinning helped. Where churn is that low, report the churn figure
   alongside the conflict count, and treat a synthetic probe (merge against a
   branch that deliberately edits the upstream hunks the fork sits on) as
   supporting evidence — clearly labelled synthetic, because it is.

   **Conflict count is not sufficient, at any churn level.** A merge that
   *deletes* a fork hook is zero-conflict, compiles, and passes `go build`.
   Thinning is what makes this possible: it makes hooks textually disjoint
   from the upstream code they modify, which is exactly what buys the clean
   merge — and exactly what lets a resolver, human or automatic, drop one
   blind. Before recording a trial merge as clean and aborting it, run
   `go build -tags=duckdb_arrow ./...` **and** the full suite
   (`go test -tags=duckdb_arrow -race ./...`) against it, not just `git merge`'s
   exit status.
3. Merge the tag into a sync branch off `fork/main`.
4. Resolve. Every resolution inside an upstream file still obeys rules 2 and 4 —
   **a conflict is not a licence to inline.** The same gap applies here as in
   step 2: a resolution can drop a hook cleanly, with no conflict marker left
   to review. Run `go build -tags=duckdb_arrow ./...` and the full suite after
   *every* resolved file, not only once at the end in step 5 — that is what
   catches a dropped hook at the resolution that dropped it, rather than
   somewhere in the aggregate of all of them.
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
