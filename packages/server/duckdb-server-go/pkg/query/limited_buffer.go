package query

import (
	"bytes"
	"errors"
)

var (
	// ErrQueryTimeout is returned when a guarded transaction's deadline elapses before the query completes.
	ErrQueryTimeout = errors.New("query: transaction deadline exceeded")

	// ErrResultTooLarge is returned when an encoded response would exceed the guarded transaction's configured
	// byte limit.
	ErrResultTooLarge = errors.New("query: encoded result exceeds configured limit")
)

// limitedBuffer is a bytes.Buffer that rejects any Write that would grow its contents past max bytes. A rejected
// Write never partially appends: it returns (0, ErrResultTooLarge) and leaves the buffer's prior contents intact.
type limitedBuffer struct {
	bytes.Buffer
	max int64
}

func newLimitedBuffer(max int64) *limitedBuffer {
	return &limitedBuffer{max: max}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(len(p)) > b.max-int64(b.Len()) {
		return 0, ErrResultTooLarge
	}
	return b.Buffer.Write(p)
}
