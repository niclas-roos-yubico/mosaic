package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func decodeHTTPParams(ctx context.Context, body io.ReadCloser, params *queryParams, expiresAt time.Time) error {
	decodeCtx, decodeCancel := contextForResolution(context.WithoutCancel(ctx), expiresAt)
	defer decodeCancel()
	ctx = decodeCtx

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
		decodeDone <- json.NewDecoder(pipeReader).Decode(params)
	}()

	select {
	case err := <-decodeDone:
		_ = body.Close()
		_ = pipeReader.Close()
		return err
	case <-ctx.Done():
		_ = body.Close()
		_ = pipeReader.CloseWithError(ctx.Err())
		err := <-decodeDone
		if resolutionExpired(expiresAt) {
			return errHTTPAuthorizationExpired
		}
		if err != nil {
			return err
		}
		return ctx.Err()
	}
}
