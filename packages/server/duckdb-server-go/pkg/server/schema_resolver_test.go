package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/stretchr/testify/require"
)

type recordingExecutor struct{ schemas []string }

func (*recordingExecutor) Exec(context.Context, string) error { return nil }
func (e *recordingExecutor) QueryArrow(_ context.Context, _ string, s []string, _ bool) ([]byte, bool, error) {
	e.schemas = append([]string(nil), s...)
	return []byte("arrow"), false, nil
}
func (e *recordingExecutor) QueryJSON(_ context.Context, _ string, s []string, _ bool) (json.RawMessage, bool, error) {
	e.schemas = append([]string(nil), s...)
	return json.RawMessage(`[]`), false, nil
}

func TestSchemaResolverSuppliesSchemas(t *testing.T) {
	exec := &recordingExecutor{}
	h := mustHandler(t, exec, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant_a"}, ExpiresAt: time.Now().Add(time.Hour)}, nil
	})))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	req.Header.Set("X-Tenant-Id", "attacker")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Equal(t, []string{"tenant_a"}, exec.schemas)
}

func TestSchemaResolverEmptySchemasFailsClosed(t *testing.T) {
	h := mustHandler(t, failOnCallExecutor{t}, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{ExpiresAt: time.Now().Add(time.Hour)}, nil
	})))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func TestSchemaResolverMakesExecAValidatedCommand(t *testing.T) {
	h := mustHandler(t, &recordingExecutor{}, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant_a"}, ExpiresAt: time.Now().Add(time.Hour)}, nil
	})))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"exec","sql":"SELECT 1"}`))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
}

func TestWebSocketClosesAtResolvedExpiry(t *testing.T) {
	expiresAt := time.Now().Add(150 * time.Millisecond)
	h := mustHandler(t, &recordingExecutor{},
		WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
			return SchemaResolution{AllowedSchemas: []string{"tenant_a"}, ExpiresAt: expiresAt}, nil
		})),
		WithWebSocket(WebSocketOptions{AllowAllOrigins: true}),
	)
	srv := newWebSocketTestServer(t, h)
	conn, _, err := srv.dial(nil)
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err = conn.Read(ctx)
	require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err), "error: %v", err)
	require.Contains(t, err.Error(), "session expired")
}

type contextCapturingExecutor struct {
	ctx context.Context
}

func (*contextCapturingExecutor) Exec(context.Context, string) error { return nil }
func (e *contextCapturingExecutor) QueryArrow(ctx context.Context, _ string, _ []string, _ bool) ([]byte, bool, error) {
	e.ctx = ctx
	return []byte("arrow"), false, nil
}
func (e *contextCapturingExecutor) QueryJSON(ctx context.Context, _ string, _ []string, _ bool) (json.RawMessage, bool, error) {
	e.ctx = ctx
	return json.RawMessage(`[]`), false, nil
}

// TestWebSocketQueryContextCarriesResolvedExpiry asserts, against a fake
// executor rather than the real DuckDB engine, that the context reaching
// execCommand over the WebSocket path carries a deadline equal to the
// resolved session expiry. A true end-to-end proof (an in-flight query
// actually aborted at expiry) needs a query slow enough to still be running
// when the deadline fires, which is impractical to make deterministic in a
// unit test; asserting the deadline on the context that reaches the executor
// is what a fake commandExecutor lets us pin down precisely.
func TestWebSocketQueryContextCarriesResolvedExpiry(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	exec := &contextCapturingExecutor{}
	h := mustHandler(t, exec,
		WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
			return SchemaResolution{AllowedSchemas: []string{"tenant_a"}, ExpiresAt: expiresAt}, nil
		})),
		WithWebSocket(WebSocketOptions{AllowAllOrigins: true}),
	)
	srv := newWebSocketTestServer(t, h)
	conn, _, err := srv.dial(nil)
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()

	require.NoError(t, wsjson.Write(srv.ctx, conn, map[string]any{
		"type": CommandJSON,
		"sql":  "SELECT 1",
	}))
	var rows []map[string]int
	require.NoError(t, wsjson.Read(srv.ctx, conn, &rows))

	require.NotNil(t, exec.ctx)
	deadline, ok := exec.ctx.Deadline()
	require.True(t, ok, "expected the query context to carry a deadline")
	require.WithinDuration(t, expiresAt, deadline, time.Millisecond)
}
