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
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err = conn.Read(ctx)
	require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err), "error: %v", err)
	require.Contains(t, err.Error(), "session expired")
}
