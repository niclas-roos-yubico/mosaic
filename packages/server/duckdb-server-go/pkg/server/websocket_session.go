package server

import (
	"context"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// beginWebSocketSession bounds a WebSocket session to the expiry carried by
// resolution. It returns the context command execution must run under and a
// cleanup function the caller defers; a zero resolution.ExpiresAt means the
// session does not expire.
//
// The session closes proactively at expiry rather than deriving a deadline
// context for wsjson.Read: github.com/coder/websocket's read-timeout handling
// force-closes the raw connection the instant a deadline context passed to
// Read is done (see (*Conn).setupReadTimeout), before a subsequent graceful
// Close(status, reason) call can write a close frame. Closing directly at
// expiry avoids that race and deterministically delivers the
// StatusPolicyViolation/"session expired" close frame to the peer.
//
// The returned query context does carry the expiry as a deadline. Unlike the
// network context it is not subject to that read/write race, and an in-flight
// query must not keep running under pre-expiry authorization past the
// session's validated exp.
//
// Every close goes through one sync.Once so an expiry and an ordinary teardown
// can never race on which status/reason the peer sees, and so the losing side
// never performs (or logs) a redundant second Close. See close.go: a second
// Close is a no-op that returns a wrapped net.ErrClosed, which would otherwise
// log an ERROR on every single legitimate expiry.
func (s *handler) beginWebSocketSession(ctx context.Context, conn *websocket.Conn, resolution SchemaResolution) (context.Context, func()) {
	var closeOnce sync.Once
	closeConn := func(status websocket.StatusCode, reason string) {
		closeOnce.Do(func() {
			if closeErr := conn.Close(status, reason); closeErr != nil {
				s.logger.Error("server: error closing websocket", "error", closeErr)
			}
		})
	}

	if resolution.ExpiresAt.IsZero() {
		return ctx, func() { closeConn(websocket.StatusInternalError, "connection closed") }
	}

	queryCtx, queryCancel := context.WithDeadline(ctx, resolution.ExpiresAt)
	expiryTimer := time.AfterFunc(time.Until(resolution.ExpiresAt), func() {
		closeConn(websocket.StatusPolicyViolation, "session expired")
	})

	// Same order the equivalent defers ran in before this moved out of
	// handleWebSocket: close the peer, stop the timer, release the deadline.
	return queryCtx, func() {
		closeConn(websocket.StatusInternalError, "connection closed")
		expiryTimer.Stop()
		queryCancel()
	}
}
