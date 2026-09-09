package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

var errHTTPAuthorizationExpired = errors.New("server: authorization expired")

func contextForResolution(parent context.Context, expiresAt time.Time) (context.Context, context.CancelFunc) {
	if expiresAt.IsZero() {
		return parent, func() {}
	}
	return context.WithDeadline(parent, expiresAt)
}

func resolutionExpired(expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !time.Now().Before(expiresAt)
}

func resolutionExpiryError() error {
	return &authorizationError{err: ErrUnauthenticated}
}

func decodeHTTPParams(ctx context.Context, w http.ResponseWriter, body io.ReadCloser, params *queryParams, expiresAt time.Time) error {
	decodeParent := ctx
	if ctx.Err() != nil {
		// Preserve the pre-existing handler contract: an already-canceled test or
		// in-memory request is decoded so authorization and execution receive its
		// canceled context. Requests canceled after admission starts still stop the
		// decoder through the ordinary request context below.
		decodeParent = context.WithoutCancel(ctx)
	}
	decodeCtx, decodeCancel := contextForResolution(decodeParent, expiresAt)
	defer decodeCancel()

	pipeReader, pipeWriter := io.Pipe()
	go func() {
		_, err := io.Copy(pipeWriter, body)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
		} else {
			_ = pipeWriter.Close()
		}
	}()

	decodeDone := make(chan error, 1)
	go func() {
		decodeDone <- decodeQueryBody(pipeReader, params)
	}()

	select {
	case err := <-decodeDone:
		_ = body.Close()
		_ = pipeReader.Close()
		return err
	case <-decodeCtx.Done():
		// FORK[http-expiry-context]: a server request body can hold its own mutex
		// while blocked in a socket read, so Close alone is not an interrupt. Set
		// the transport read deadline first; ResponseController reaches the real
		// connection through supported ResponseWriter wrappers.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		_ = body.Close()
		_ = pipeReader.CloseWithError(decodeCtx.Err())
		if resolutionExpired(expiresAt) {
			return errHTTPAuthorizationExpired
		}
		return decodeCtx.Err()
	}
}
