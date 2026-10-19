# Dataset access

The public dataset API is a REST-only `POST /api/data/` route owned by the
platform gateway. It accepts the existing Mosaic JSON or Arrow query body plus
`dataset_ids`, `type`, `sql`, and `persist`. The gateway rejects `persist: true`,
`exec`, and WebSocket upgrades. The standalone Mosaic binary retains its
upstream WebSocket handler for internal compatibility; it is not the public
dataset endpoint, and a deployment must expose the REST gateway instead.

## Dataset session policy

Dataset sessions carry a `dataset_policy` claim with:

- `context_id` and `valid_until`;
- `datasets`, whose entries contain `dataset_id`, `mirror_id`,
  `binding_revision`, `data_version`, `target_schema`, `target_table`, and
  `prefix`.

The policy expiry is bounded by the JWT expiry. The platform minter uses the
same second-truncated expiry for both values. The gateway obtains these fields
from the authorizer and publication resolver; clients cannot choose a mirror
ID, version, binding revision, schema, table, or prefix.

Production dataset mode must start the binary with
`--require-dataset-policy=true`. This rejects legacy schema-only sessions. The
flag defaults to false only for explicit legacy fixtures and the privileged
internal Quack process; those modes are not the public dataset API.

Each request must declare a nonempty, unique list of at most 256 dataset UUIDs.
The gateway authorizes exactly that list and strips it before forwarding the
Mosaic JSON or Arrow request. The session policy then permits only the exact
qualified target relations bound to those dataset UUIDs. Schema-only fallback
is unavailable in dataset mode.

## Mirror and query checks

The transactional binding verifier checks `bqsync_internal.mirror_state` for
the trusted `mirror_id`, `data_version`, and `prefix`, then checks the target
view in the same transaction. A target view must be the platform-generated
single-source shape `SELECT * FROM read_parquet('<trusted-prefix>/*.parquet')`.
Additional base relations, joins, subqueries, other table functions, computed
paths, and mismatched prefixes are denied. This same-transaction check prevents
a target name from authorizing a replacement source or a catalog-repointed
view.

Queries are validated and materialized transactionally, bounded to 30 seconds
per request and the configured result-byte limit, and buffered until final
authorization succeeds. Authorization expiry or revocation aborts the request.

The allowed metadata forms are `DESCRIBE SELECT * FROM <exact-target>` and
`SUMMARIZE SELECT * FROM <exact-target>`, with the target relation still subject
to the same policy and live-view checks. Catalog enumeration and arbitrary
metadata queries are denied. `exec` is always denied.
