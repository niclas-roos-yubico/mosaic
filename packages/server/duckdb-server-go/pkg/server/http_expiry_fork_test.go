package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

type expiryTestBody struct {
	io.Reader
	until     time.Time
	closed    chan struct{}
	readDone  chan struct{}
	closeOnce sync.Once
}

func (b *expiryTestBody) Read(p []byte) (int, error) {
	defer close(b.readDone)
	if delay := time.Until(b.until); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-b.closed:
			return 0, io.ErrClosedPipe
		}
	}
	return b.Reader.Read(p)
}

func (b *expiryTestBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

type expiryTestExecutor struct {
	mu       sync.Mutex
	contexts []context.Context
	query    func(context.Context) (json.RawMessage, error)
}

func (*expiryTestExecutor) Exec(context.Context, string) error { return nil }

func (e *expiryTestExecutor) QueryArrow(ctx context.Context, _ string, _ []string, _ bool) ([]byte, bool, error) {
	e.mu.Lock()
	e.contexts = append(e.contexts, ctx)
	e.mu.Unlock()
	return nil, false, nil
}

func (e *expiryTestExecutor) QueryJSON(ctx context.Context, _ string, _ []string, _ bool) (json.RawMessage, bool, error) {
	e.mu.Lock()
	e.contexts = append(e.contexts, ctx)
	e.mu.Unlock()
	if e.query == nil {
		return json.RawMessage(`[]`), false, nil
	}
	result, err := e.query(ctx)
	return result, false, err
}

func (e *expiryTestExecutor) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.contexts)
}

func TestHTTPExpiryRejectsBodyCompletingAfterResolution(t *testing.T) {
	expiresAt := time.Now().Add(40 * time.Millisecond)
	started := time.Now()
	executor := &expiryTestExecutor{}
	h := mustHandler(t, executor, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant"}, ExpiresAt: expiresAt}, nil
	})))

	body := &expiryTestBody{
		Reader: strings.NewReader(`{"type":"json","sql":"SELECT 1"}`),
		until:  expiresAt.Add(30 * time.Millisecond), closed: make(chan struct{}), readDone: make(chan struct{}),
	}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Zero(t, executor.callCount())
	require.Less(t, time.Since(started), 500*time.Millisecond)
	select {
	case <-body.readDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("request-body reader was not unblocked at authorization expiry")
	}
}

func TestHTTPExpiryBoundsInFlightQuery(t *testing.T) {
	expiresAt := time.Now().Add(45 * time.Millisecond)
	executor := &expiryTestExecutor{
		query: func(ctx context.Context) (json.RawMessage, error) {
			<-ctx.Done()
			return nil, fmt.Errorf("%w: %v", query.ErrQueryTimeout, ctx.Err())
		},
	}
	h := mustHandler(t, executor, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant"}, ExpiresAt: expiresAt}, nil
	})))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)

	require.Equal(t, http.StatusGatewayTimeout, res.Code)
	require.NotContains(t, res.Body.String(), `[]`)
	require.Equal(t, 1, executor.callCount())
}

func TestHTTPExpiryContextPreservesOrdinaryAuthorizedRequest(t *testing.T) {
	expiresAt := time.Now().Add(time.Second)
	executor := &expiryTestExecutor{}
	h := mustHandler(t, executor, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant"}, ExpiresAt: expiresAt}, nil
	})))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `[]`, res.Body.String())
	require.Equal(t, 1, executor.callCount())
	e := executor.contexts[0]
	deadline, ok := e.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, expiresAt, deadline, 20*time.Millisecond)
}

func TestHTTPExpiryRejectsAlreadyExpiredGET(t *testing.T) {
	executor := &expiryTestExecutor{}
	h := mustHandler(t, executor, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant"}, ExpiresAt: time.Now().Add(-time.Millisecond)}, nil
	})))

	req := httptest.NewRequest(http.MethodGet, "/?type=json&sql=SELECT+1", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Zero(t, executor.callCount())
}

func TestHTTPExpiryDiscardsLateSuccessfulExecutorResult(t *testing.T) {
	expiresAt := time.Now().Add(40 * time.Millisecond)
	executor := &expiryTestExecutor{
		query: func(context.Context) (json.RawMessage, error) {
			time.Sleep(time.Until(expiresAt) + 20*time.Millisecond)
			return json.RawMessage(`[{"late":true}]`), nil
		},
	}
	h := mustHandler(t, executor, WithSchemaResolver(SchemaResolverFunc(func(*http.Request) (SchemaResolution, error) {
		return SchemaResolution{AllowedSchemas: []string{"tenant"}, ExpiresAt: expiresAt}, nil
	})))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"json","sql":"SELECT 1"}`))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.NotContains(t, res.Body.String(), `late`)
}
