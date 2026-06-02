package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/internal/query"
)

type Command string

const (
	CommandArrow Command = "arrow"
	CommandExec  Command = "exec"
	CommandJSON  Command = "json"
)

type QueryParams struct {
	Type    *Command `json:"type"`
	SQL     *string  `json:"sql"`
	Persist *bool    `json:"persist"`
	Name    *string  `json:"name"`
}

// schemaForbiddenError is returned when a query references a schema outside allowed_schemas.
type schemaForbiddenError struct {
	Schema string
}

func (e *schemaForbiddenError) Error() string {
	return fmt.Sprintf("schema_forbidden: %s", e.Schema)
}

// forbiddenBody is the contract §2.4 response body.
type forbiddenBody struct {
	Error   string `json:"error"`
	Details string `json:"details"`
}

// Server handles HTTP and WebSocket requests, validating session JWTs and enforcing schema access.
type Server struct {
	*http.ServeMux

	db           *query.DB
	jwtValidator *JWTValidator // nil in tests that don't need a real DB

	logger *slog.Logger
}

// NewWithJWTValidator constructs the server with JWT-based schema enforcement.
// db may be nil in tests that only exercise the auth layer.
// validator is required for production; if nil the server rejects all requests.
func NewWithJWTValidator(db *query.DB, validator *JWTValidator, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		ServeMux:     mux,
		db:           db,
		jwtValidator: validator,
		logger:       logger,
	}

	mux.Handle("/", corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
			strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			s.handleWebSocket(w, r)
		} else {
			s.handleHTTP(w, r)
		}
	})))

	return s
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Request-Method", "*")
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, POST, GET")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "2592000")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateSessionJWT reads X-Platform-Session from the request, validates it, and returns
// the allowed_schemas on success. Returns (nil, error) on any failure.
// IMPORTANT: This function MUST NOT log the X-Platform-Session value (§12 redaction).
func (s *Server) validateSessionJWT(r *http.Request) ([]string, error) {
	if s.jwtValidator == nil {
		return nil, fmt.Errorf("jwt validator not configured")
	}
	token := r.Header.Get("X-Platform-Session")
	if token == "" {
		return nil, fmt.Errorf("missing X-Platform-Session header")
	}
	claims, err := s.jwtValidator.Validate(r.Context(), token)
	if err != nil {
		// Log the failure without the token value (§12 redaction).
		s.logger.Warn("server: session JWT validation failed", "error", err)
		return nil, err
	}
	return claims.AllowedSchemas, nil
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	allowedSchemas, err := s.validateSessionJWT(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionContextTakeover,
	})
	if err != nil {
		s.logger.Error("server: failed to accept websocket connection", "error", err)
		return
	}

	defer func() {
		err = conn.Close(websocket.StatusInternalError, "connection closed")
		if err != nil {
			s.logger.Error("server: error closing websocket", "error", err)
		}
	}()

	for {
		err = s.handleWebSocketMessage(r.Context(), conn, allowedSchemas)
		if err != nil {
			s.logger.Error("server: websocket error, breaking connection", "error", err)
			break
		}
	}
}

// only return an error if you want to close the connection
func (s *Server) handleWebSocketMessage(ctx context.Context, conn *websocket.Conn, allowedSchemas []string) error {
	var params QueryParams
	err := wsjson.Read(ctx, conn, &params)
	if err != nil {
		return fmt.Errorf("failed to read websocket message: %w", err)
	}

	data, _, err := s.execCommand(context.TODO(), params, allowedSchemas)
	if err != nil {
		var sfErr *schemaForbiddenError
		if errors.As(err, &sfErr) {
			body, _ := json.Marshal(forbiddenBody{Error: "schema_forbidden", Details: sfErr.Schema})
			writeErr := conn.Write(ctx, websocket.MessageText, body)
			if writeErr != nil {
				return fmt.Errorf("server: failed to write forbidden response: %w", writeErr)
			}
			return nil
		}
		writeErr := wsjson.Write(ctx, conn, map[string]string{"error": err.Error()})
		if writeErr != nil {
			return fmt.Errorf("server: failed to write error response: %w", writeErr)
		}
		return nil
	}

	switch *params.Type {
	case CommandExec:
		err = conn.Write(ctx, websocket.MessageText, []byte("{}"))
		if err != nil {
			return fmt.Errorf("server: failed to write exec response: %w", err)
		}

	case CommandArrow:
		err = conn.Write(ctx, websocket.MessageBinary, data)
		if err != nil {
			return fmt.Errorf("server: failed to write arrow response: %w", err)
		}

	case CommandJSON:
		err = conn.Write(ctx, websocket.MessageText, data)
		if err != nil {
			return fmt.Errorf("server: failed to write json response: %w", err)
		}

	default:
		panic("server: unknown command type:" + *params.Type)
	}

	return nil
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	allowedSchemas, err := s.validateSessionJWT(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated"})
		return
	}

	var params QueryParams

	switch r.Method {
	case http.MethodPost:
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			s.logger.Error("server: failed to decode request body", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	case http.MethodGet:
		q := r.URL.Query()
		queryType := q.Get("type")
		sqlQuery := q.Get("sql")

		if queryType != "" {
			cmd := Command(queryType)
			params.Type = &cmd
		}
		if sqlQuery != "" {
			params.SQL = &sqlQuery
		}

	default:
		s.logger.Error("server: invalid method", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, cacheHit, err := s.execCommand(r.Context(), params, allowedSchemas)
	if err != nil {
		var sfErr *schemaForbiddenError
		if errors.As(err, &sfErr) {
			// §12: log denied query attempt (SQL is logged; token is NEVER logged).
			s.logger.Warn("server: query denied — schema_forbidden",
				"schema", sfErr.Schema,
				"sql_preview", sqlPreview(params),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(forbiddenBody{Error: "schema_forbidden", Details: sfErr.Schema})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch *params.Type {
	case CommandExec:
		w.WriteHeader(http.StatusOK)

	case CommandArrow:
		w.Header().Set("Content-Type", "application/vnd.apache.arrow.stream")
		if cacheHit {
			w.Header().Set("Cache-Status", "mosaic-duckdb-go; hit")
		}
		_, err = w.Write(data)
		if err != nil {
			s.logger.Error("server: failed to write Arrow data", "error", err)
		}

	case CommandJSON:
		w.Header().Set("Content-Type", "application/json")
		if cacheHit {
			w.Header().Set("Cache-Status", "mosaic-duckdb-go; hit")
		}
		_, err = w.Write(data)
		if err != nil {
			s.logger.Error("server: failed to write JSON data", "error", err)
		}

	default:
		panic("server: unknown command type:" + *params.Type)
	}
}

func (s *Server) execCommand(ctx context.Context, params QueryParams, allowedSchemas []string) ([]byte, bool, error) {
	err := params.Validate(s.logger)
	if err != nil {
		return nil, false, err
	}

	useCache := false
	if params.Persist != nil {
		useCache = *params.Persist
	}

	switch *params.Type {
	case CommandExec:
		// exec commands do not carry an AST suitable for schema-enforcement; they pass through.
		return nil, false, s.db.Exec(ctx, *params.SQL)

	case CommandArrow:
		data, hit, qErr := s.db.QueryArrow(ctx, *params.SQL, allowedSchemas, useCache)
		if qErr != nil {
			return nil, false, wrapSchemaError(qErr)
		}
		return data, hit, nil

	case CommandJSON:
		data, hit, qErr := s.db.QueryJSON(ctx, *params.SQL, allowedSchemas, useCache)
		if qErr != nil {
			return nil, false, wrapSchemaError(qErr)
		}
		return data, hit, nil

	default:
		panic("server: unknown command type:" + *params.Type)
	}
}

func (p QueryParams) Validate(logger *slog.Logger) error {
	if p.Type == nil || *p.Type == "" {
		logger.Error("server: missing required 'type' parameter")
		return errors.New("missing required 'type' parameter")
	}

	switch *p.Type {
	case CommandArrow, CommandExec, CommandJSON:
	default:
		logger.Error("server: invalid 'type' parameter", "type", *p.Type)
		return errors.New("invalid 'type' parameter: " + string(*p.Type))
	}

	if p.SQL == nil || *p.SQL == "" {
		logger.Error("server: missing required 'sql' parameter")
		return errors.New("missing required 'sql' parameter")
	}

	return nil
}

// wrapSchemaError detects schema-access errors from the query layer and wraps them
// in a schemaForbiddenError so the server can return the correct 403 body.
// The query layer uses two error message prefixes (internal/query/validator.go):
//   - "access denied: unauthorized access to schema '%v'" (line 201)
//   - "access denied: unauthorized access to table '%v' with empty schema" (line 196)
//
// Both are schema-access denials and are wrapped into schemaForbiddenError.
func wrapSchemaError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "access denied: unauthorized access to schema") {
		// Format: "... access denied: unauthorized access to schema '<schema_name>'"
		schema := extractSchemaFromError(msg, "unauthorized access to schema ")
		return &schemaForbiddenError{Schema: schema}
	}
	if strings.Contains(msg, "access denied: unauthorized access to table") &&
		strings.Contains(msg, "with empty schema") {
		// Format: "... access denied: unauthorized access to table '<table_name>' with empty schema"
		details := extractSchemaFromError(msg, "unauthorized access to table ")
		return &schemaForbiddenError{Schema: details}
	}
	return err
}

// extractSchemaFromError extracts the relevant detail string from a schema-access
// denial error. It returns the portion of msg that follows the given prefix,
// stripped of surrounding single quotes and any trailing suffix (e.g. " with empty schema").
// Returns the full msg if the prefix is not found.
func extractSchemaFromError(msg, prefix string) string {
	idx := strings.Index(msg, prefix)
	if idx < 0 {
		return msg
	}
	rest := strings.TrimSpace(msg[idx+len(prefix):])
	// Strip the trailing " with empty schema" suffix if present (table variant).
	rest = strings.TrimSuffix(rest, " with empty schema")
	// Strip surrounding single quotes produced by the '%s' format verb.
	rest = strings.Trim(rest, "'")
	return rest
}

// sqlPreview returns the first 200 characters of a SQL query for logging — safe to log
// since this is query content, not a token. Truncated to avoid log bloat.
func sqlPreview(params QueryParams) string {
	if params.SQL == nil {
		return ""
	}
	s := *params.SQL
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
