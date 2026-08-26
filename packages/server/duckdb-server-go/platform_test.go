package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FORK: unit cover for the two platform.go pieces no other test exercises directly. addLogFields is
// the one that matters: it exists so upstream's config literal stays byte-identical, and a key
// silently vanishing from it would not fail any other test in this package.
func testPlatformConfig() *platformConfig {
	jwks := "https://example.invalid/jwks"
	issuer := "https://example.invalid/platform"
	alg := "RS256"
	external := false
	noCache := false
	timeout := 30 * time.Second
	maxBytes := int64(64 << 20)
	fd := -1
	return &platformConfig{
		jwksURL: &jwks, jwtIssuer: &issuer, jwtAlgorithm: &alg,
		enableExternalAccess: &external, disableResultCache: &noCache,
		transactionTimeout: &timeout, maxQueryResultBytes: &maxBytes, quackBootstrapFD: &fd,
	}
}

func TestAddLogFieldsCarriesEveryHardenedKeyAndNoSecret(t *testing.T) {
	p := testPlatformConfig()
	fd := 7
	p.quackBootstrapFD = &fd

	config := map[string]interface{}{"database": ":memory:"}
	p.addLogFields(config)

	require.Equal(t, false, config["external_access_enabled"])
	require.Equal(t, false, config["result_cache_disabled"])
	require.Equal(t, "30s", config["query_transaction_timeout"])
	require.Equal(t, int64(64<<20), config["max_query_result_bytes"])
	require.Equal(t, true, config["quack_bootstrap_configured"])
	require.Equal(t, ":memory:", config["database"], "upstream's own keys must survive untouched")

	// The descriptor number itself is never logged, only whether one is configured.
	require.NotContains(t, config, "quack_bootstrap_fd")
	for key, value := range config {
		require.NotEqual(t, 7, value, "descriptor number leaked into %q", key)
	}
}

func TestQueryOptionsGateOnTheirFlags(t *testing.T) {
	p := testPlatformConfig()
	require.Len(t, p.queryOptions(nil), 2, "allowlist and remote-URI rejection are unconditional")

	external, noCache := true, true
	p.enableExternalAccess, p.disableResultCache = &external, &noCache
	require.Len(t, p.queryOptions(nil), 4, "guarded mode adds the cache-disable and transaction guard")
}
