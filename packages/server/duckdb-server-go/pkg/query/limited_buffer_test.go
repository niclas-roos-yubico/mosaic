package query

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimitedBufferExactBoundary(t *testing.T) {
	b := newLimitedBuffer(4)
	n, err := b.Write([]byte("1234"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	n, err = b.Write([]byte("5"))
	require.Zero(t, n)
	require.True(t, errors.Is(err, ErrResultTooLarge))
	require.Equal(t, "1234", b.String())
}
