# DuckDB Go Server

A Go-based server that runs a local DuckDB instance and support queries over Web Sockets or HTTP/HTTPS, returning data in either [Apache Arrow](https://arrow.apache.org/) or JSON format.

_Note:_ This package provides a local DuckDB server. To instead use DuckDB-WASM in the browser, use the `wasmConnector` in the [`mosaic-core`](https://github.com/uwdata/mosaic/tree/main/packages/mosaic/mosaic-core) package.

## Usage

Install the server with `go install`.

```sh
go install -tags=duckdb_arrow github.com/uwdata/mosaic/packages/server/duckdb-server-go@latest
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
-   `--cache-ttl <duration>`: Time-to-live for cache entries as a Go duration. 0s means no expiration (e.g., '10m', '1h'). Defaults to 0s.
-   `--cert <path>`: Path to a TLS certificate file to enable HTTPS.
-   `--key <path>`: Path to a TLS private key file to enable HTTPS.
-   `--platform-session-jwks-url`: URL of the platform session JWKS endpoint (e.g. `http://platform-svc/.well-known/jwks.json`). **Required** — the server refuses to start without it. Used to validate the `X-Platform-Session` JWT on every query (see Schema Access Control below).
-   `--platform-jwt-iss`: Expected `iss` for session JWTs. Defaults to `https://<umbrella-host>/platform`. Must match the token minter.
-   `--platform-jwt-alg`: Expected signing algorithm for session JWTs (`RS256` or `ES256`). Defaults to `RS256`. `none` and HMAC algorithms are always rejected.
-   `--load-extensions`: Comma-separated list of extensions to install and load at startup. Use a pipe after the extension name to specify the repository. Unspecified repositories will default to 'core'. (e.g. `mysql_scanner,netquack|community,aws|core_nightly`
-   `--function-blocklist`: Comma-separated list of functions to block, useful for blocking functions that may pose security or performance risks. (e.g., 'bigquery_query,read_parquet')`

By default, the server will look for `localhost.pem` and `localhost-key.pem` in the current directory to enable HTTPS if the `--cert` and `--key` flags are not provided.

Create certificates for localhost with [mkcert](https://github.com/FiloSottile/mkcert)

```sh
mkcert -install # Install mkcert CA
mkcert localhost # create localhost.pem and localhost-key.pem
```

### Schema Access Control (session-JWT enforcement)

This fork replaces the upstream `--schema-match-headers` mechanism (which trusted raw request
headers) with validation of a signed **session JWT**. Every query must carry an `X-Platform-Session`
header containing a JWT; the server validates it against the configured JWKS and enforces the token's
`allowed_schemas` claim via the existing AST validator.

1. **Client / gateway side**: a trusted minter issues a short-lived JWT with an `allowed_schemas`
   claim (the schemas the caller may read), plus standard `iss`/`aud`/`exp`/`nbf`/`sub`/`jti` claims.
   The JWT is forwarded to this server in the `X-Platform-Session` request header on every query.
2. **Server side**: start the server with `--platform-session-jwks-url` (required), and optionally
   `--platform-jwt-iss` / `--platform-jwt-alg`. On each request the server:
   - fetches and caches the JWKS (conditional GET; refreshes on `kid` miss; **fails closed** if the
     JWKS is unreachable on first use),
   - verifies the signature and validates `iss`, `aud` (`platform-data-plane`), `exp`, `nbf` (≤60s
     clock skew), and rejects `none`/HMAC algorithms,
   - extracts `allowed_schemas` and passes it to the AST validator.
3. **Responses**: a missing/invalid/expired token returns **401** `{"error":"unauthenticated"}`.
   A query referencing a schema outside `allowed_schemas` returns **403**
   `{"error":"schema_forbidden","details":"<schema>"}`. The `X-Platform-Session` value is never logged.

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
go build -o duckdb-server-go .
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
