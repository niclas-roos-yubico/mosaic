package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time" // FORK: WebSocket expiry enforcement.

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/niclas-roos-yubico/mosaic/packages/server/duckdb-server-go/pkg/query"
)

type queryParams struct {
	Type    *CommandType `json:"type"`
	SQL     *string      `json:"sql"`
	Persist *bool        `json:"persist"`
	Name    *string      `json:"name"`
}

type commandResponse struct {
	data        []byte
	cacheHit    bool
	contentType string
	wsMessage   websocket.MessageType
}

var commandResponses = map[CommandType]commandResponse{
	CommandExec:  {wsMessage: websocket.MessageText},
	CommandArrow: {contentType: "application/vnd.apache.arrow.stream", wsMessage: websocket.MessageBinary},
	CommandJSON:  {contentType: "application/json", wsMessage: websocket.MessageText},
}

type queryParamsError string

func (e queryParamsError) Error() string {
	return string(e)
}

// commandExecutor is private so the server package does not expose query's
// current schema-policy plumbing as a supported extension point.
type commandExecutor interface {
	Exec(context.Context, string) error
	QueryArrow(context.Context, string, []string, bool) ([]byte, bool, error)
	QueryJSON(context.Context, string, []string, bool) (json.RawMessage, bool, error)
}

type handler struct {
	db                 commandExecutor
	schemaMatchHeaders []string
	// FORK: JWT-derived schema/expiry resolution, see schema_resolver.go.
	schemaResolver   SchemaResolver
	logger           *slog.Logger
	authorizer       Authorizer
	httpHandler      http.Handler
	websocketOptions WebSocketOptions
}

// New constructs a Mosaic HTTP and WebSocket handler backed by db. Omitting
// WithAuthorizer preserves unrestricted command behavior.
func New(db *query.DB, opts ...Option) (http.Handler, error) {
	if db == nil {
		return nil, errors.New("server: database is required")
	}

	cfg, err := applyOptions(opts)
	if err != nil {
		return nil, err
	}

	return newHandler(db, cfg), nil
}

func newHandler(db commandExecutor, cfg config) *handler {
	s := &handler{
		db:                 db,
		schemaMatchHeaders: cfg.schemaMatchHeaders,
		schemaResolver:     cfg.schemaResolver, // FORK: JWT-derived schema/expiry resolution.
		logger:             cfg.logger,
		authorizer:         cfg.authorizer,
		websocketOptions:   cfg.websocket,
	}

	s.httpHandler = newCORSHandler(cfg.cors, cfg.corsProtection, http.HandlerFunc(s.handleHTTP))

	return s
}

func (s *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.handleWebSocket(w, r)
		return
	}

	s.httpHandler.ServeHTTP(w, r)
}

func (s *handler) commandAuthorizer(r *http.Request) (CommandAuthorizer, error) {
	if s.authorizer == nil {
		return nil, nil
	}

	authorize, err := s.authorizer.AuthorizeRequest(r)
	if err != nil {
		return nil, &authorizationError{err: err}
	}
	if authorize == nil {
		return nil, &authorizationError{err: errNoCommandAuthorizer}
	}

	return authorize, nil
}

func (s *handler) writeHTTPError(w http.ResponseWriter, err error) {
	response := s.classifyAndLogError(err)
	http.Error(w, response.message, response.status)
}

// FORK: resolve JWT-derived schemas and expiry without coupling server to platformauth.
func (s *handler) requestSchemas(r *http.Request) (SchemaResolution, error) {
	if s.schemaResolver != nil {
		resolution, err := s.schemaResolver.ResolveSchemas(r)
		if err != nil {
			return SchemaResolution{}, &authorizationError{err: err}
		}
		if len(resolution.AllowedSchemas) == 0 {
			return SchemaResolution{}, &authorizationError{err: ErrUnauthenticated}
		}
		return resolution, nil
	}
	return SchemaResolution{AllowedSchemas: getAllowedSchemas(r, s.schemaMatchHeaders)}, nil
}

func (s *handler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !webSocketOriginAllowed(r, s.websocketOptions) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// FORK: resolve schemas/expiry via requestSchemas instead of reading headers directly.
	resolution, err := s.requestSchemas(r)
	if err != nil {
		s.writeHTTPError(w, err)
		return
	}
	allowedSchemas := resolution.AllowedSchemas
	if len(s.schemaMatchHeaders) > 0 && len(allowedSchemas) == 0 {
		s.logger.Error("server: no allowed schemas found in request headers", "headers", s.schemaMatchHeaders)
		http.Error(w, "no allowed schemas found in request headers", http.StatusUnauthorized)
		return
	}

	authorize, err := s.commandAuthorizer(r)
	if err != nil {
		s.writeHTTPError(w, err)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: s.websocketOptions.AllowAllOrigins,
		OriginPatterns:     s.websocketOptions.AllowedOrigins,
		CompressionMode:    websocket.CompressionContextTakeover,
	})
	if err != nil {
		s.logger.Error("server: failed to accept websocket connection", "error", err)
		return
	}

	// FORK: bound the session to the resolved expiry (validated JWT exp), closing with 1008.
	//
	// This proactively closes at expiry rather than deriving a deadline context
	// for wsjson.Read: github.com/coder/websocket's read-timeout handling
	// force-closes the raw connection the instant a deadline context passed to
	// Read is done (see (*Conn).setupReadTimeout), before a subsequent graceful
	// Close(status, reason) call can write a close frame. Closing directly at
	// expiry avoids that race and deterministically delivers the
	// StatusPolicyViolation/"session expired" close frame to the peer.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if !resolution.ExpiresAt.IsZero() {
		expiryTimer := time.AfterFunc(time.Until(resolution.ExpiresAt), func() {
			if closeErr := conn.Close(websocket.StatusPolicyViolation, "session expired"); closeErr != nil {
				s.logger.Error("server: error closing websocket", "error", closeErr)
			}
		})
		defer expiryTimer.Stop()
	}

	defer func() {
		if closeErr := conn.Close(websocket.StatusInternalError, "connection closed"); closeErr != nil {
			s.logger.Error("server: error closing websocket", "error", closeErr)
		}
	}()

	for {
		err = s.handleWebSocketMessage(ctx, conn, allowedSchemas, authorize)
		if err != nil {
			s.logger.Error("server: websocket error, breaking connection", "error", err)
			break
		}
	}
}

// A returned error closes the connection. Command errors are written to the
// client and return nil so the session survives them.
func (s *handler) handleWebSocketMessage(ctx context.Context, conn *websocket.Conn, allowedSchemas []string, authorize CommandAuthorizer) error {
	var params queryParams
	err := wsjson.Read(ctx, conn, &params)
	if err != nil {
		return fmt.Errorf("failed to read websocket message: %w", err)
	}

	response, err := s.execCommand(ctx, params, allowedSchemas, authorize)
	if err != nil {
		errResponse := s.classifyAndLogError(err)
		writeErr := wsjson.Write(ctx, conn, map[string]string{
			"error": errResponse.message,
			"code":  errResponse.code,
		})
		if writeErr != nil {
			return fmt.Errorf("server: failed to write error response: %w", writeErr)
		}

		return nil
	}

	payload := response.data
	if response.contentType == "" {
		payload = []byte("{}")
	}
	if err = conn.Write(ctx, response.wsMessage, payload); err != nil {
		return fmt.Errorf("server: failed to write response: %w", err)
	}

	return nil
}

func (s *handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// FORK: resolve schemas/expiry via requestSchemas instead of reading headers directly.
	resolution, err := s.requestSchemas(r)
	if err != nil {
		s.writeHTTPError(w, err)
		return
	}
	allowedSchemas := resolution.AllowedSchemas
	if len(s.schemaMatchHeaders) > 0 && len(allowedSchemas) == 0 {
		s.logger.Error("server: no allowed schemas found in request headers", "headers", s.schemaMatchHeaders)
		http.Error(w, "no allowed schemas found in request headers", http.StatusUnauthorized)
		return
	}

	authorize, err := s.commandAuthorizer(r)
	if err != nil {
		s.writeHTTPError(w, err)
		return
	}

	var params queryParams

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
			cmd := CommandType(queryType)
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

	response, err := s.execCommand(r.Context(), params, allowedSchemas, authorize)
	if err != nil {
		s.writeHTTPError(w, err)
		return
	}

	if response.contentType == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", response.contentType)
	if response.cacheHit {
		w.Header().Set("Cache-Status", "mosaic-duckdb-go; hit")
	}
	if _, err = w.Write(response.data); err != nil {
		s.logger.Error("server: failed to write response", "error", err, "content_type", response.contentType)
	}
}

func (s *handler) execCommand(ctx context.Context, params queryParams, allowedSchemas []string, authorize CommandAuthorizer) (commandResponse, error) {
	if err := params.Validate(s.logger); err != nil {
		return commandResponse{}, err
	}
	response := commandResponses[*params.Type]
	var err error

	command := newCommand(*params.Type, *params.SQL)
	if authorize != nil {
		if err = authorize(ctx, command); err != nil {
			return commandResponse{}, &authorizationError{err: err}
		}
	}

	useCache := false
	if params.Persist != nil {
		useCache = *params.Persist
	}

	switch command.Type() {
	case CommandExec:
		// FORK: either schema policy makes unrestricted exec unsafe.
		if len(s.schemaMatchHeaders) > 0 || s.schemaResolver != nil {
			return commandResponse{}, query.ErrExecWithValidation
		}
		err = s.db.Exec(ctx, command.SQL())

	case CommandArrow:
		response.data, response.cacheHit, err = s.db.QueryArrow(ctx, command.SQL(), allowedSchemas, useCache)

	case CommandJSON:
		response.data, response.cacheHit, err = s.db.QueryJSON(ctx, command.SQL(), allowedSchemas, useCache)

	default:
		return commandResponse{}, fmt.Errorf("server: no executor for command type %q", command.Type())
	}

	return response, err
}

func (p queryParams) Validate(logger *slog.Logger) error {
	if p.Type == nil || *p.Type == "" {
		logger.Error("server: missing required 'type' parameter")
		return queryParamsError("missing required 'type' parameter")
	}

	if _, ok := commandResponses[*p.Type]; !ok {
		logger.Error("server: invalid 'type' parameter", "type", *p.Type)
		return queryParamsError("invalid 'type' parameter: " + string(*p.Type))
	}

	if p.SQL == nil || *p.SQL == "" {
		logger.Error("server: missing required 'sql' parameter")
		return queryParamsError("missing required 'sql' parameter")
	}

	return nil
}

func getAllowedSchemas(req *http.Request, schemaMatchHeaders []string) []string {
	var allowedSchemas []string

	for _, matchHeader := range schemaMatchHeaders {
		allowedSchema := req.Header.Get(strings.TrimSpace(matchHeader))
		if allowedSchema != "" {
			allowedSchemas = append(allowedSchemas, allowedSchema)
		}
	}

	return allowedSchemas
}
