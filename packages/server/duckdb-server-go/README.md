# DuckDB Go Server

A Go-based server that runs a local DuckDB instance and support queries over Web Sockets or HTTP/HTTPS, returning data in either [Apache Arrow](https://arrow.apache.org/) or JSON format.

_Note:_ This package provides a local DuckDB server. To instead use DuckDB-WASM in the browser, use the `wasmConnector` in the [`mosaic-core`](https://github.com/uwdata/mosaic/tree/main/packages/mosaic/mosaic-core) package.

## Usage

Install the server with `go install`.

```sh
go install -tags=duckdb_arrow github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go@latest
```

Then run the server with

```sh
duckdb-server-go
```

### Command-Line Options

You can customize the server behavior with the following command-line flags:

-   `--database <path>`: Path to a DuckDB database file (e.g., "database.db"). Defaults to an in-memory database.
-   `--address <address>`: The HTTP address to listen on. Defaults to "localhost".
-   `--port <port>`: The HTTP port to listen on. Defaults to "3000".
-   `--connection-pool-size <size>`: The maximum size of the connection pool. Defaults to 10.
-   `--max-cache-entries <size>`: The maximum number of cache entries. Defaults to 1000.
-   `--max-cache-bytes <bytes>`: Max number of cache size in bytes (overrides max-cache-entries if both are set). Defaults to 0 (no limit).
-   `--cache-ttl <duration>`: Time-to-live for cache entries as a Go duration. 0s means no expiration (e.g., '10m', '1h'). Defaults to 0s. Not a freshness or authorization control once `--disable-result-cache=true` — see **Platform Security Mode**.
-   `--cert <path>`: Path to a TLS certificate file to enable HTTPS.
-   `--key <path>`: Path to a TLS private key file to enable HTTPS.
-   `--schema-match-headers`: Comma-separated list of headers to match against schema names for multi-tenant access control (e.g., `X-Tenant-Id,verified-user-id`).
    In this build, any non-empty value is rejected at startup — schemas come from the validated session JWT. See **Platform Security Mode**.
-   `--load-extensions`: Comma-separated list of extensions to install and load at startup. Use a pipe after the extension name to specify a DuckDB repository alias. Unspecified repositories use DuckDB's default (e.g. `mysql_scanner,netquack|community,aws|core_nightly`).
-   `--function-blocklist`: Comma-separated list of exact function names to block, useful for blocking functions that may pose security or performance risks (e.g. `bigquery_query,read_parquet`).
    In this build, any non-empty value is rejected at startup — see **Platform Security Mode**.
-   `--function-allowlist`: Comma-separated list of exact function names to add to the reviewed defaults. Names are matched case-insensitively, repeated flags accumulate names, and an explicitly empty value enables only the defaults. This build always applies the reviewed defaults regardless of this flag — see **Platform Security Mode**.

By default, the server will look for `localhost.pem` and `localhost-key.pem` in the current directory to enable HTTPS if the `--cert` and `--key` flags are not provided.

For compatibility, the installed binary permits all HTTP and WebSocket origins. A cross-site page can therefore submit
commands, including side-effecting `exec` commands over GET, to a running server. Do not expose the binary to untrusted
browsers or cookie credentials without an outer proxy that enforces an origin or CSRF policy. Programs embedding
`pkg/server` instead receive safe zero-value origin defaults and can configure exact allowed origins.

Create certificates for localhost with [mkcert](https://github.com/FiloSottile/mkcert)

```sh
mkcert -install # Install mkcert CA
mkcert localhost # create localhost.pem and localhost-key.pem
```

### Platform Security Mode

The `duckdb-server-go` binary built from this fork always requires a platform session JWT and always applies
the reviewed function-call policy (see **Function Policies** below). Passing `--enable-external-access=true`
additionally activates a transactional catalog guard around every query. The flags below configure that
contract; none of them are optional extras.

| Flag | Default | Effect |
| --- | --- | --- |
| `--platform-session-jwks-url` | *(required, no default)* | JWKS endpoint used to verify `X-Platform-Session`. Startup refuses to run without it. |
| `--platform-jwt-iss` | `https://<umbrella-host>/platform` | Expected JWT `iss`. The default is a placeholder — every token fails `invalid_issuer` until this is set to the real issuer. |
| `--platform-jwt-alg` | `RS256` | The one allowed JWT signing algorithm. `none` and any HMAC algorithm (`HS256`/`HS384`/`HS512`) are rejected at startup regardless of this flag's value. |
| `--enable-external-access` | `false` | `false` latches DuckDB's `enable_external_access` off permanently for the process. `true` keeps it on and activates the transactional catalog guard described below; requires `--disable-result-cache=true`. |
| `--disable-result-cache` | `false` | Disables the server-side persisted SQL result cache. Required whenever `--enable-external-access=true`. |
| `--query-transaction-timeout` | `30s` | Maximum guarded-query duration: pool wait, live catalog check, execution, and materialization together. Must be positive. Only meaningful when `--enable-external-access=true`. |
| `--max-query-result-bytes` | `67108864` (64 MiB) | Maximum encoded JSON/Arrow response size for a guarded query. Must be positive. |
| `--quack-bootstrap-fd` | `-1` (disabled) | Inherited file descriptor carrying a versioned Quack bootstrap payload. Requires `--enable-external-access=true`. |

Startup runs the following checks, in order, immediately after parsing flags and before any listener,
connector, or JWKS fetch is created. Each failure prints one line to stderr and exits `1`, so the message is
greppable in whatever supervises the process:

1. `--platform-session-jwks-url is required`
2. `--quack-bootstrap-fd must be -1 or at least 3`
3. `--quack-bootstrap-fd requires --enable-external-access=true`
4. `--enable-external-access=true requires --disable-result-cache=true`
5. `--query-transaction-timeout must be positive`
6. `--max-query-result-bytes must be positive`
7. `function blocklist is not permitted; use the reviewed allowlist`
8. `--schema-match-headers is not permitted; schemas are derived from the validated session JWT`

If the process exits `1` with none of these eight messages, none of these conditions were violated — look at
the next startup failure instead (invalid `--load-extensions`, a rejected JWT algorithm, a connector error),
which is logged rather than printed to stderr.

### Security Boundary

**Session authentication.** Every HTTP and WebSocket request must carry the session JWT in the
`X-Platform-Session` header. A missing header, an invalid signature, or a token that otherwise fails
validation gets HTTP 401 immediately, before any command is decoded or executed. The JWT must include `sub`,
`jti`, `exp`, and a non-empty `allowed_schemas` claim; any one missing fails validation. The expected audience
is hardcoded to `platform-data-plane` inside the binary — it is never a flag, so it cannot be loosened by
configuration. The validator accepts a token up to 60 seconds early or late (a fixed internal default, not
exposed as a flag), but that acceptance skew never extends a WebSocket's close deadline — see below.

**Session expiry.** A WebSocket connection closes with status 1008 and reason `session expired` at the exact
instant the token's validated `exp` arrives — even if the upgrade happened earlier, and even if a query
admitted just before expiry is still running (the query's own context shares that deadline). The 60-second
acceptance skew above is deliberately not added to this deadline. The current data-platform internal session
token has a five-minute TTL, so a long-lived dashboard connection reconnects at least that often; a reconnect
obtains a fresh token through the normal platform proxy path and is a routine event, never a restart of the
underlying Mosaic DuckDB child process.

**Schema authorization.** Programs embedding `pkg/server` scope queries to specific schemas with
`server.WithSchemaResolver`, which supplies both the allowed schemas and (optionally) an expiry for each
request; an empty schema list is treated as unauthenticated, never as "no restriction." This platform
binary's resolver, `platformauth.SchemaResolver()`, derives `AllowedSchemas` and `ExpiresAt` exclusively from
the validated JWT's `allowed_schemas` and `exp` claims — request headers are never consulted, so a client
cannot widen its own access by adding one. As with any schema-based policy here: it assumes a single catalog
(attached catalogs are outside this boundary), explicitly catalog-qualified table/`SHOW`/function references
are rejected outright, and the policy does not restrict catalog metadata returned by functions such as
`duckdb_tables()` or `pragma_table_info()`.

**`exec` is always denied.** Three independent layers enforce this in the shipped binary: the JWT authorizer
rejects `CommandExec` outright (403); the handler's structural policy guard independently rejects it (400)
whenever a schema resolver is configured, which it always is here, regardless of whether the authorizer is
even wired up; and the query package's own policy refuses `exec` whenever a function allowlist or
remote-URI-literal rejection is configured, which this binary also always does. `json` and `arrow` are the
only commands a client can issue. This is also why Mosaic pre-aggregation must be disabled client-side — see
below.

**Function allowlist and remote URI rejection are always on.** The reviewed default function allowlist and
remote-URI-literal rejection (both documented below) are unconditionally active in this binary; there is no
flag to turn either off, and `--function-allowlist` only adds names on top of the defaults.

> **Operational note — what extending the allowlist actually grants.** Remote-URI-literal rejection is a
> real, independently tested mechanism (see **Remote URI Literal Policy** below), not a theoretical one. But
> as of this writing, no function in the reviewed default allowlist accepts a path or file/URI argument
> (verified: zero overlap between the default allowlist and the set of remote-read-capable functions). Under
> an all-defaults configuration the allowlist alone already denies every remote read, so URI rejection is
> redundant with it — the allowlist would deny the same request even if URI rejection were disabled. That
> changes the moment an operator adds a remote-capable function (`read_parquet`, `read_csv`, `st_read`, ...)
> via `--function-allowlist`: from that point on, URI rejection is the only thing standing between that
> function and an arbitrary remote fetch. Treat every allowlist addition of a path/URI-accepting function as
> widening remote-network exposure, not just the SQL surface.

**External access modes.**

-   *Latched (`--enable-external-access=false`, the default).* The extension initializer installs and loads
    extensions on the first physical connection while external access is still on; startup then calls
    `DisableExternalAccess`, which flips DuckDB's `enable_external_access` off globally for the rest of the
    process — DuckDB itself refuses to re-enable it while the database is running. No transactional catalog
    guard runs in this mode. Quack is unavailable (mutually exclusive with this mode).
-   *Guarded (`--enable-external-access=true`).* Required for Quack and for the BigQuery mirror deployment;
    requires `--disable-result-cache=true`. Every `json`/`arrow` request runs on one physical connection,
    inside one transaction: validation (`system.main.json_serialize_sql`) as the first statement after
    `BeginTx`; then a live catalog check — every referenced relation must resolve to a physical table in
    that same snapshot, and the catalog must contain no user-defined macro; then execution; then full
    materialization into a bounded in-memory buffer. Only a successful commit of all of that releases any
    byte to the HTTP or WebSocket client; a timeout, cancellation, oversized result, or failed commit rolls
    back and discards the connection instead of returning it to the pool.

    > **Operational note — the live catalog check is not free.** It costs roughly 10-19ms per guarded
    > query, turning a ~1-2ms query into ~11-21ms. That's negligible against the 30-second default, but it
    > is not "cheap," and it is a hard floor on `--query-transaction-timeout`: any value below roughly 20ms
    > rejects every query at the catalog-check stage before it ever executes, which looks identical to a
    > client-visible timeout on every single request.

    > **Operational note — the macro check is catalog-wide, not per-query.** `duckdb_functions()` must
    > report zero user-defined macros *anywhere in the catalog* for a guarded query to proceed — not just
    > macros the failing query itself references. DuckDB's serialized query AST cannot reliably distinguish
    > a plain table reference from a table-macro call, so the only sound check is catalog-wide rather than
    > per-reference. The consequence: **a single `CREATE MACRO`, by any user, in any schema, denies 100% of
    > guarded queries process-wide** until that macro is dropped. If every query is suddenly failing with a
    > catalog-related 403, look for a stray macro first — `DROP` it and queries resume immediately; no
    > restart is needed.
-   *Quack bootstrap (`--quack-bootstrap-fd >= 3`).* Requires `--enable-external-access=true`; mutually
    exclusive with latched mode. Startup reads a versioned bootstrap payload from the inherited descriptor:
    the descriptor must be at least 3, the payload at most 4 KiB of JSON with no unknown or trailing fields,
    `version` exactly `1`, `port` in 1-65535, and `token` a base64url string that decodes to exactly 32
    bytes. That typed, decoded config drives exactly one fixed statement,
    `CALL quack_serve('quack:127.0.0.1:<port>', token => ..., allow_other_hostname => false, disable_ssl =>
    true)`, with the port and token passed as bound parameters — the bootstrap payload is never SQL, and
    this path never accepts a caller-supplied statement, public or admin. The resulting connection is held
    for the life of the process, separate from the public HTTP/WebSocket surface: it is a privileged,
    loopback-only write channel for a trusted external writer (e.g. the BigQuery mirror's Loader), not a way
    for platform clients to bypass `exec` denial.

**Result caching.** `--disable-result-cache=true` disables the server's persisted SQL result cache entirely
and is mandatory whenever `--enable-external-access=true`. In that combination, a request's `persist: true`
field is silently ignored — the guarded code path never reads or writes the cache, by construction.
`--cache-ttl` still exists for the unguarded path's cache; once the result cache is disabled there is nothing
left for a TTL to expire, so it must not be treated as a freshness or authorization control.

There is no `--catalog-invariant-refresh` flag, no catalog ticker, no land-triggered process restart, and no
cache-invalidation epoch in this version — the per-transaction live catalog check above is the only freshness
mechanism, and there is no background process keeping a cached view of the catalog current.

**BigQuery mirror configuration.** The mirror's supervised child argv must include, in addition to
`--platform-session-jwks-url` and the other flags every deployment needs:

```text
--enable-external-access=true
--disable-result-cache=true
--query-transaction-timeout=30s
--max-query-result-bytes=67108864
--quack-bootstrap-fd=3
```

It deliberately omits `--cache-ttl`: the result cache is off in this mode, so a TTL has nothing to act on. A
successful land replaces the target table in place (`CREATE OR REPLACE TABLE ... AS SELECT ...`) without
restarting the Mosaic DuckDB child.

**Mosaic clients must disable pre-aggregation.** Mosaic pre-aggregation issues `exec` to create schemas and
materialized views; since `exec` is always denied here, pre-aggregation fails on every selection update
unless it is turned off client-side:

```js
const mc = new Coordinator(undefined, { preagg: { enabled: false } });
```

`options` is the Coordinator's **second** constructor parameter. Writing `new Coordinator({ preagg: {
enabled: false } })` — one argument — silently binds that object to the *connector* parameter instead, leaves
`options` at its default, and leaves pre-aggregation **enabled**, with no error raised anywhere. Always pass
the connector (or `undefined`, if attaching later via `coordinator(mc)`) as the first argument and the
options object as the second.

### Failure Modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Every request returns 401 `unauthenticated` | Missing/expired/malformed `X-Platform-Session`, or the token is missing `sub`/`jti`/`exp`/`allowed_schemas` | Confirm the proxy is attaching a fresh session JWT; confirm `--platform-jwt-iss`/`--platform-jwt-alg`/`--platform-session-jwks-url` match the real issuer, not the placeholder default |
| WebSocket closes with code 1008, reason `session expired` | Normal — the session JWT's `exp` arrived | Reconnect; expect this at least every five minutes (current internal token TTL) |
| `exec` always fails (403 or 400) | By design — this binary denies `exec` unconditionally | Use `json`/`arrow`; disable Mosaic pre-aggregation client-side (`preagg: { enabled: false }`, two-argument `Coordinator` form) |
| A query that used to work now 403s "not a physical table" | The relation is a view, or was replaced by one | Query the underlying physical table |
| **Every** guarded query suddenly 403s, including ones touching no macro | Someone ran `CREATE MACRO` anywhere in the catalog — the check is catalog-wide | Find and `DROP` the macro; queries recover immediately, no restart needed |
| A query 403s "not in the allowlist" | The function isn't in the reviewed defaults | Add it via `--function-allowlist=name`; if it accepts a path/URI, you're now also relying on remote-URI rejection (see above) |
| Startup refuses `--function-blocklist=...` | Blocklists aren't supported by this binary | Use `--function-allowlist` instead |
| Startup refuses `--schema-match-headers=...` | Header-derived schemas aren't supported by this binary | Nothing to do — schemas come from the session JWT's `allowed_schemas` |
| Every guarded query times out (504) near-instantly | `--query-transaction-timeout` set below ~20ms | The live catalog check alone costs ~10-19ms; raise the timeout |
| 413 `response_too_large` | Result exceeds `--max-query-result-bytes` | Narrow the query, or raise the flag with the pool-size × cap memory budget in mind |
| `--platform-jwt-alg=HS256` (or similar) refuses to start | HMAC and `none` algorithms are always rejected | Use `RS256` (or another asymmetric algorithm the JWKS actually publishes) |
| Server exits `1` immediately on startup | A startup-mode validation check failed | Read the stderr line — it names the exact flag/combination; see the ordered list above |

### Programmatic Extension Initialization

Use `pkg/extensions` from a DuckDB connector callback:

```go
connector, err := duckdb.NewConnector(":memory:", func(execer driver.ExecerContext) error {
	return extensions.ParseAndInstall(connectorCtx, execer, "httpfs", "netquack|community")
})
```

Repository suffixes are DuckDB aliases. Use `InstallAndLoadFromCustomRepository` for repository URLs or paths, and
`LoadInstalled`, `LoadFile`, or `InstallAndLoadFile` for pre-provisioned extensions. The callback runs for every physical
connection; use a long-lived context and call `PingContext` before serving to force initialization. The first failure
aborts the connection. Extensions are trusted native code, so load only trusted repositories and files.

### Programmatic Authorization

Programs embedding `pkg/server` should authenticate with standard HTTP middleware around the handler returned by
`server.New`, then use `server.WithAuthorizer` only for command-aware policy. `AuthorizeRequest` runs once before POST
decoding or WebSocket upgrade and returns a `CommandAuthorizer` called for every decoded command, including each
WebSocket message, before policy validation, cache lookup, or execution. If it reads `r.Body`, it must restore it; both
authorizers must be concurrency-safe. Outer middleware must decide whether CORS preflight `OPTIONS` requests may reach
the server.

Omitting `WithAuthorizer` preserves unrestricted behavior; a configured authorizer that fails or returns nil fails
closed. `ErrUnauthenticated`, `ErrPermissionDenied`, and `ErrInvalidCommand` map to HTTP 401, 403, and 400; unexpected
errors are logged and returned as sanitized 500 responses. Authorization can allow or deny the normalized command type
and exact SQL, but cannot rewrite SQL or sandbox the shared process, filesystem, network, extensions, catalogs, or
credentials.

### Function Policies

Use an allowlist when the server should accept only reviewed functions and operators. An explicitly empty value enables
the defaults without adding application-specific names:

```sh
duckdb-server-go --function-allowlist=
```

Without `--function-allowlist`, a server built directly on `pkg/query` remains unrestricted. This fork's
`duckdb-server-go` binary is the exception: it always calls `WithFunctionAllowlist`, so the reviewed defaults
are active even when `--function-allowlist` is never passed — see **Platform Security Mode** above. The flag
intentionally exposes only policy activation and exact additions; use a custom binary embedding `pkg/query`
for exclusions, exact-only policies, or extension groups.

Programs embedding `pkg/query` can apply the same policy and add application functions with:

```go
query.WithFunctionAllowlist(query.FunctionAllowlistOptions{
	Include: append(functionset.Spatial.Elevated(), "my_function"),
})
```

By default, configured policies use `functionset.DefaultFunctions()`, which contains reviewed built-ins and every
[core extension](https://duckdb.org/docs/current/core_extensions/overview)'s `Compute()` group. `Elevated()` requires
explicit admission, and `All()` returns both groups. These Go helpers return fresh slices; the CLI accepts exact names only.

The table records unique names reviewed against DuckDB 1.5.5. A name is elevated if any overload has elevated behavior.
An empty row means the extension has no reviewed function-call names, not that it has no other capabilities.

| Extension | Compute | Elevated | Classification and status |
| --- | ---: | ---: | --- |
| `Autocomplete` | 1 | 3 | Parser check; completion and parser controls are elevated. |
| `Avro` | 0 | 1 | Reader only. |
| `AWS` | 0 | 1 | Credential and provider operation. |
| `Azure` | 0 | 0 | Filesystem integration with no reviewed function-call names. |
| `Delta` | 2 | 9 | Local parser/test helpers; scans, metadata I/O, and writes are elevated. |
| `DuckLake` | 1 | 21 | Local hash helper; catalog, scan, metadata, and mutation operations are elevated. |
| `Encodings` | 0 | 0 | CSV codec integration with no reviewed function-call names. |
| `Excel` | 2 | 1 | Value conversion; the sheet reader is elevated. |
| `FTS` | 1 | 2 | Text stemming; index creation and mutation are elevated. |
| `HTTPFS` | 0 | 0 | Filesystem integration with no reviewed function-call names. |
| `Iceberg` | 2 | 14 | Value helpers; scans, catalogs, metadata I/O, and writes are elevated. |
| `ICU` | 179 | 7 | Deterministic collation and calendar computation; current-time names are elevated. |
| `Inet` | 11 | 0 | IP value operations only. |
| `JSON` | 33 | 9 | Value parsing and serialization; readers, SQL execution, and plan inspection are elevated. |
| `Lance` | 0 | 12 | Source-pinned scans and metadata operations. |
| `MotherDuck` | 0 | 198 | Best-effort observed proprietary runtime snapshot; all names are elevated. |
| `MySQL` | 0 | 5 | Connector and scanner operations. |
| `ODBC` | 0 | 11 | Connector and scanner operations. |
| `Parquet` | 2 | 9 | `VARIANT` conversion; file, metadata, bloom, and key operations are elevated. |
| `Postgres` | 2 | 8 | Value helpers; connector and scanner operations are elevated. |
| `Quack` | 3 | 9 | Protocol value helpers; remote and session operations are elevated. |
| `Spatial` | 151 | 13 | Geometry computation; readers, index/catalog access, random generation, and resource-capable transforms are elevated. |
| `SQLite` | 0 | 3 | Connector and scanner operations. |
| `TPCDS` | 2 | 2 | Query and answer text; data generators are elevated. |
| `TPCH` | 2 | 2 | Query and answer text; data generators are elevated. |
| `UI` | 0 | 5 | HTTP server lifecycle, URL, and status operations. |
| `UnityCatalog` | 0 | 4 | Attached-catalog and checkpoint operations; the generated registry is incomplete. |
| `Vortex` | 0 | 2 | Readers verified against the pinned nested source revision. |
| `VSS` | 0 | 5 | Index access and management operations. |

These groups authorize names only; extension loading and file or network access are separate concerns. Function-policy
validation is syntactic and name-only: it does not bind function identity, inspect arguments, expand macros or views,
recursively inspect SQL strings, or cover replacement scans and attached-table binding. Keep catalogs and the search path
trusted, and enforce resource access outside this policy. Pre-provisioned views and attached tables can deliberately expose
curated datasets while reader functions remain excluded; catalog integrity and process resource controls then carry the
boundary.

In Go, `Exclude` wins over `Include`, and `DisableDefaults` creates an exact-only policy. Omitting
`WithFunctionAllowlist` is unrestricted; configuring an exact-empty policy denies all function calls. A function
allowlist cannot be combined with a non-empty blocklist, and any configured function policy rejects `exec` requests.

Spatial compute defaults cover Mosaic rendering over existing geometry data, but the `ST_Read` loader remains elevated.
Current-time functions are omitted from defaults because persistent cache entries do not expire by default; keyword forms
such as `CURRENT_DATE` are not function nodes and remain outside this policy.

### Remote URI Literal Policy

Programs embedding `pkg/query` can make a best-effort to reject caller-supplied remote file locations while keeping local
file readers enabled:

```go
db, err := query.New(ctx, connector,
	query.WithRemoteURILiteralRejection(),
)
```

The option rejects recognized remote URI literals in DuckDB replacement scans, such as
`FROM 'gcs://bucket/file.parquet'`, and in the reviewed positional and named path arguments of
[remote-read-capable functions](./pkg/functionset/remoteread/README.md). It also
checks literal lists and every decoded string literal within a path expression, so
`read_parquet('gcs://' || 'bucket/file.parquet')` is rejected. Only reviewed path arguments are checked; unrelated values
such as `WHERE url = 'https://example.com'` remain unaffected. Ordinary local paths without a recognized marker remain
usable; a local path string containing one of the markers is intentionally rejected.

Matching is case-insensitive and rejects a literal if it contains any prefix reviewed against DuckDB 1.5.5's pinned
[HTTP](https://github.com/duckdb/duckdb-httpfs/blob/827222fb45a043a7a852d1f7aae46901492a3cda/src/httpfs.cpp#L808-L810),
[S3-compatible](https://github.com/duckdb/duckdb-httpfs/blob/827222fb45a043a7a852d1f7aae46901492a3cda/src/s3fs.cpp#L843-L848),
[Hugging Face](https://github.com/duckdb/duckdb-httpfs/blob/827222fb45a043a7a852d1f7aae46901492a3cda/src/include/hffs.hpp#L33-L35),
[Azure Blob](https://github.com/duckdb/duckdb-azure/blob/003214c96d0caa39d5c3e27a9e1976a0692c7d37/src/azure_blob_filesystem.cpp#L32-L36),
and [Azure DFS](https://github.com/duckdb/duckdb-azure/blob/003214c96d0caa39d5c3e27a9e1976a0692c7d37/src/azure_dfs_filesystem.cpp#L27-L34)
filesystem handlers:

```text
http://  https://  s3://  s3a://  s3n://  gcs://
gs://    r2://     hf://  azure://  az://   abfs://  abfss://
```

DuckDB's generated
[extension-prefix map](https://github.com/duckdb/duckdb/blob/v1.5.5/src/include/duckdb/main/extension_entries.hpp#L1275-L1280)
is a useful autoloading cross-check, but it is not exhaustive: the pinned Azure DFS filesystem also accepts `abfs://`.

Trusted initialization can still load filesystem extensions and attach remote Iceberg or other catalogs before accepting
queries. Queries against those attached catalogs use catalog and table identifiers rather than caller-supplied URI
literals, so they remain usable. Enabling this policy rejects all `exec` commands and rejects the known nested-SQL
binders and executors `query`, `json_execute_serialized_sql`, and `json_serialize_plan` outright. `json` and `arrow`
requests are limited to statements DuckDB can serialize for validation. Connector initialization is outside that command
path.

DuckDB's serialized AST does not distinguish a replacement-scan string from a quoted table or CTE identifier, so a
URI-shaped identifier is rejected too.

This is intentionally incomplete hardening against common accidental or opportunistic remote scans, not a filesystem or
network sandbox. Split or otherwise computed path values can evade detection when no individual literal contains a
complete reviewed prefix, as in `'gc' || 's://bucket/file.parquet'`. Macros and views are not expanded, and unreviewed
extensions can define other nested-SQL executors, reader functions, or schemes. Other known gaps include GDAL virtual
paths such as `/vsis3/`, local Iceberg or Delta metadata that refers to remote files, and SQL stored in a local SQLite
view. Keep catalogs, extensions, and initialization SQL trusted, and restrict the server process's filesystem, network,
and credentials independently.

This platform's `duckdb-server-go` binary always enables this policy together with the default function
allowlist — see **Platform Security Mode** above for how the two combine in practice, and in particular for
why remote-URI rejection is currently structural defense in depth rather than the only thing denying remote
reads under an all-defaults configuration.

## API

The server supports queries via HTTP GET and POST, and WebSockets. The GET endpoint is useful for debugging. For example, you can query it with [this url](<http://localhost:3000/?query={"sql":"select 1","type":"json"}>).

Each endpoint takes a JSON object with a command in the `type`. The server supports the following commands.

### `exec`

Executes the SQL query in the `sql` field.

### `arrow`

Executes the SQL query in the `sql` field and returns the result in Apache Arrow format.

### `json`

Executes the SQL query in the `sql` field and returns the result in JSON format.

## Developers

### Build

Build the release binary with:

```sh
go build -tags=duckdb_arrow -o duckdb-server-go .
```

### Develop

To run the server, use `go run` (this won't restart when the code changes):

```sh
go run -tags=duckdb_arrow .
```

Before sending a pull request, run the tests, linter, and formatter:

```sh
go fmt ./...
go test -tags=duckdb_arrow ./...
golangci-lint run
```

### Update Dependencies

Update dependencies with `go get -u` and then run `go mod tidy` to clean up the `go.mod` file.
