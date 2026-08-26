package main

import (
	"context"
	"database/sql/driver"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/duckdb/duckdb-go/v2"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/extensions"
	// FORK: hardened platform-session JWT auth, wired into run() below (Task 2/4/10).
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/platformauth"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	dbPath := flag.String("database", ":memory:", "Path of database file (e.g., \"database.db\". \":memory:\" for in-memory database)")
	address := flag.String("address", "localhost", "HTTP Address")
	port := flag.String("port", "3000", "HTTP Port")
	poolSize := flag.Int("connection-pool-size", 10, "Max connection pool size")
	maxCacheEntries := flag.Int("max-cache-entries", 1000, "Max number of cache entries")
	maxCacheBytes := flag.Int("max-cache-bytes", 0, "Max number of cache size in bytes (overrides max-cache-entries if both are set)")
	ttlStr := flag.String("cache-ttl", "0s", "Time-to-live for cache entries as a Go duration. 0s means no expiration (e.g., '10m', '1h'). Defaults to 0s.")
	certFile := flag.String("cert", "", "Path to TLS certificate file (optional, enables HTTPS)")
	keyFile := flag.String("key", "", "Path to TLS private key file (optional, enables HTTPS)")
	schemaMatchHeadersStr := flag.String("schema-match-headers", "", "Comma-separated list of headers to match against schema names for multi-tenant access control (e.g., \"X-Tenant-Id,verified-user-id\")")
	extensionsStr := flag.String("load-extensions", "", "Comma-separated list of extensions to install and load at startup. Use a pipe after the extension name to specify a DuckDB repository alias. Unspecified repositories use DuckDB's default (e.g. mysql_scanner,netquack|community,aws|core_nightly).")
	functionBlocklistStr := flag.String("function-blocklist", "", "Comma-separated list of functions to block, useful for blocking functions that may pose security or performance risks. (e.g., 'bigquery_query,read_parquet')")
	var functionAllowlist optionalCommaListFlag
	flag.Var(&functionAllowlist, "function-allowlist", "Comma-separated exact names to add to the reviewed default allowlist. An empty value enables only the defaults; names are matched case-insensitively.")

	platform := registerPlatformFlags() // FORK[platform-flags]: hardened-mode flags must be declared on the default FlagSet before upstream's flag.Parse
	flag.Parse()

	// FORK[startup-validation]: must run after flag.Parse and before any resource is allocated
	if err := platform.validate(*schemaMatchHeadersStr, *functionBlocklistStr); err != nil {
		return 1
	}

	var schemaMatchHeaders []string
	if *schemaMatchHeadersStr != "" {
		schemaMatchHeaders = strings.Split(*schemaMatchHeadersStr, ",")
	}

	var functionBlocklist []string
	if *functionBlocklistStr != "" {
		functionBlocklist = strings.Split(*functionBlocklistStr, ",")
	}

	ctx := context.Background()

	logLevel := slog.LevelDebug
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	if err := extensions.Validate(*extensionsStr); err != nil {
		logger.Error("main: invalid load-extensions", "error", err, "load-extensions", *extensionsStr)
		return 1
	}

	// If no certificate files are specified, check for default localhost certificates
	if *certFile == "" && *keyFile == "" {
		// Check if localhost.pem and localhost-key.pem exist in the current directory
		if _, err := os.Stat("localhost.pem"); err == nil {
			if _, err = os.Stat("localhost-key.pem"); err == nil {
				*certFile = "localhost.pem"
				*keyFile = "localhost-key.pem"
				logger.Info("main: found default certificates in current directory", "cert", *certFile, "key", *keyFile)
			}
		}
	}

	// FORK: the connector now installs extensions via the Task 8 install-once initializer instead of
	// an inline closure that re-ran ParseAndInstall (a full INSTALL) on every physical connection. See
	// extension_init.go: only the first connection INSTALLs; every later connection only LOADs, which
	// (unlike INSTALL) does not require external access.
	connector, err := duckdb.NewConnector(*dbPath, newExtensionInitializer(ctx, *extensionsStr))
	if err != nil {
		logger.Error("main: error creating duckdb connector", "error", err)
		return 1
	}
	defer func() {
		err = connector.Close()
		if err != nil {
			logger.Error("main: error closing duckdb connector", "error", err)
		}
	}()

	ttl, err := time.ParseDuration(*ttlStr)
	if err != nil {
		logger.Error("main: invalid cache-ttl", "error", err)
		return 1
	}

	// FORK: the reviewed function allowlist and remote-URI-literal rejection are now unconditional
	// (Task 10), not opt-in: query.WithFunctionAllowlist always runs, and functionAllowlist.values is
	// nil when --function-allowlist is omitted, so functionset.DefaultFunctions still applies via
	// query.resolveFunctionAllowlist. query.WithFunctionBlocklist keeps upstream's call site; startup
	// validation guarantees the slice is empty.
	queryOptions := []query.OptionFunc{
		query.WithMaxConnections(*poolSize),
		query.WithMaxCacheEntries(*maxCacheEntries),
		query.WithMaxCacheBytes(*maxCacheBytes),
		query.WithTTL(ttl),
		query.WithLogger(logger),
		query.WithFunctionAllowlist(query.FunctionAllowlistOptions{Include: functionAllowlist.values}),
		query.WithRemoteURILiteralRejection(),
		query.WithFunctionBlocklist(functionBlocklist),
	}
	if *platform.disableResultCache {
		queryOptions = append(queryOptions, query.WithResultCacheDisabled())
	}
	if *platform.enableExternalAccess {
		queryOptions = append(queryOptions, query.WithTransactionalCatalogGuard(query.TransactionOptions{
			Timeout: *platform.transactionTimeout, MaxResultBytes: *platform.maxQueryResultBytes,
		}))
	}

	db, err := query.New(ctx, connector, queryOptions...)
	if err != nil {
		logger.Error("main: error creating query DB", "error", err)
		return 1
	}
	defer db.Close()

	// FORK: external-access latch (Task 8/10), applied only in external-access-off mode. This is the
	// first statement in run() to force sql.DB to open a physical connection (DisableExternalAccess
	// issues SET through db.db), so the install-once initializer's INSTALL step above runs while
	// external access is still enabled, and only then does this latch drop it -- globally and
	// irreversibly, per external_access_global_test.go -- before any query-serving connection needs
	// one. Quack mode (below) requires --enable-external-access=true and is mutually exclusive with
	// this branch, so this branch is always skipped -- never entered -- when Quack is active.
	if !*platform.enableExternalAccess {
		if err := db.DisableExternalAccess(ctx); err != nil {
			logger.Error("main: failed to latch external access", "error", err)
			return 1
		}
		enabled, err := db.ExternalAccessEnabled(ctx)
		if err != nil || enabled {
			logger.Error("main: external access latch verification failed", "error", err)
			return 1
		}
	}

	// FORK: Quack bootstrap (Task 9/10). Starts before the public listener; the returned connection is
	// held via defer for the lifetime of the process so the writer stays alive. No error path below
	// logs the descriptor number, token, config, or payload.
	var quackConn driver.Conn
	if *platform.quackBootstrapFD >= 3 {
		cfg, err := readQuackBootstrapFD(*platform.quackBootstrapFD)
		if err != nil {
			logger.Error("main: failed to read Quack bootstrap", "error", err)
			return 1
		}
		quackConn, err = startQuack(ctx, connector, cfg)
		if err != nil {
			logger.Error("main: failed to start Quack", "error", err)
			return 1
		}
		defer func() {
			if err := quackConn.Close(); err != nil {
				logger.Error("main: failed to close Quack connection", "error", err)
			}
		}()
	}

	// FORK: platform session JWT validator (Task 2/10). Audience is hardcoded, never a flag.
	validator, err := platformauth.NewJWTValidator(platformauth.JWTValidatorConfig{
		JWKSURL: *platform.jwksURL, Issuer: *platform.jwtIssuer,
		Audience: "platform-data-plane", Algorithms: []string{*platform.jwtAlgorithm},
	})
	if err != nil {
		logger.Error("main: error creating platform session validator", "error", err)
		return 1
	}

	// FORK: two of the three independent exec-denial gates are wired here: platformauth.Authorizer()
	// (gate 1, denies CommandExec outright) and server.WithSchemaResolver (gate 2, which arms the
	// schema-policy guard in pkg/server/server.go's execCommand). The third gate -- the query
	// package's own policy in (*query.DB).Exec -- is active unconditionally in this binary because
	// WithFunctionAllowlist and WithRemoteURILiteralRejection above are always applied, independent of
	// --enable-external-access. server.WithSchemaMatchHeaders is called with upstream's value, which
	// startup validation guarantees is empty; schemas always come from the validated JWT via
	// WithSchemaResolver.
	s, err := server.New(db,
		server.WithSchemaMatchHeaders(schemaMatchHeaders...),
		server.WithAuthorizer(platformauth.Authorizer()),
		server.WithSchemaResolver(platformauth.SchemaResolver()),
		server.WithLogger(logger),
		server.WithCORS(server.CORSOptions{
			AllowAllOrigins: true,
			AllowAllHeaders: true,
			MaxAge:          30 * 24 * time.Hour,
		}),
		server.WithWebSocket(server.WebSocketOptions{AllowAllOrigins: true}),
	)
	if err != nil {
		logger.Error("main: error creating server", "error", err)
		return 1
	}
	logger.Warn("DuckDB Server permits all HTTP and WebSocket origins for compatibility; enforce an outer origin or CSRF policy before exposing it to untrusted browsers")

	// FORK: every request must carry a validated platform session JWT before it reaches s.
	// platformauth.Middleware passes OPTIONS through untouched (see its doc comment), so it cannot
	// disturb the CORS-preflight/method-switch composition already inside s: s's own CORS handler
	// still intercepts OPTIONS and its method switch still returns 405 for anything but GET/POST
	// before execCommand or authorize ever run.
	handler := platformauth.Middleware(validator, logger)(s)

	// FORK: startup log carries only booleans and numeric limits for the hardened-mode flags -- never
	// the Quack descriptor number, the bootstrap token/payload, or X-Platform-Session.
	config := map[string]interface{}{
		"database":                      *dbPath,
		"address":                       *address,
		"port":                          *port,
		"connection_pool_size":          *poolSize,
		"cache_size":                    *maxCacheEntries,
		"cert_file":                     *certFile,
		"key_file":                      *keyFile,
		"schema_match_headers":          *schemaMatchHeadersStr,
		"ttl":                           ttl,
		"max_cache_bytes":               *maxCacheBytes,
		"load_extensions":               *extensionsStr,
		"function_blocklist":            *functionBlocklistStr,
		"function_allowlist":            functionAllowlist.String(),
		"function_allowlist_configured": functionAllowlist.set,
		"external_access_enabled":       *platform.enableExternalAccess,
		"result_cache_disabled":         *platform.disableResultCache,
		"query_transaction_timeout":     platform.transactionTimeout.String(),
		"max_query_result_bytes":        *platform.maxQueryResultBytes,
		"quack_bootstrap_configured":    *platform.quackBootstrapFD >= 3,
	}
	logger.Info("DuckDB Server configuration", "config", config)

	extensions, err := db.GetExtensions(ctx)
	if err != nil {
		logger.Error("main: error getting extensions", "error", err)
		return 1
	}

	logger.Info("DuckDB Server Extensions", "extensions", extensions)

	fmt.Println("DuckDB Server Extensions:")
	fmt.Printf("%-20s | %-8s | %-20s | %-20s\n", "name", "version", "repository", "install_mode")
	fmt.Println("-------------------- | -------- | -------------------- | --------------------")
	for _, extension := range extensions {
		fmt.Printf("%-20s | %-8s | %-20s | %-20s\n", extension.Name, extension.Version, extension.Repository, extension.InstallMode)
	}
	fmt.Println("-------------------- | -------- | -------------------- | --------------------")

	addr := *address + ":" + *port

	// Check if both certificate files are provided for HTTPS
	// FORK: the listener now serves handler (platformauth.Middleware wrapping s), not s directly.
	if *certFile != "" && *keyFile != "" {
		logger.Info(fmt.Sprintf("DuckDB Server listening on https://%s and wss://%s", addr, addr))
		err = http.ListenAndServeTLS(addr, *certFile, *keyFile, handler)
	} else {
		if *certFile != "" || *keyFile != "" {
			logger.Warn("main: both cert and key files must be provided for HTTPS. Falling back to HTTP")
		}
		logger.Info(fmt.Sprintf("DuckDB Server listening on http://%s and ws://%s", addr, addr))
		err = http.ListenAndServe(addr, handler)
	}
	if err != nil {
		logger.Error("main: error running HTTP server", "error", err)
		return 1
	}
	return 0
}
