package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type requestBoundsExecutor struct{}

func (requestBoundsExecutor) Exec(context.Context, string) error { return nil }
func (requestBoundsExecutor) QueryArrow(context.Context, string, []string, bool) ([]byte, bool, error) {
	return nil, false, nil
}
func (requestBoundsExecutor) QueryJSON(context.Context, string, []string, bool) (json.RawMessage, bool, error) {
	return json.RawMessage(`[]`), false, nil
}

func TestHTTPQueryRejectsOversizeAndTrailingDocuments(t *testing.T) {
	h := mustHandler(t, requestBoundsExecutor{})
	valid := []byte(`{"type":"json","sql":"SELECT 1"}`)
	for _, tc := range []struct {
		name   string
		body   []byte
		status int
	}{
		{"oversize", append(valid, []byte(strings.Repeat(" ", int(MaxQueryBodyBytes)))...), http.StatusRequestEntityTooLarge},
		{"trailing", append(valid, []byte(`{"type":"json","sql":"SELECT 2"}`)...), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.body))
			if tc.name == "oversize" {
				req.ContentLength = -1
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != tc.status {
				t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
			}
		})
	}
}
