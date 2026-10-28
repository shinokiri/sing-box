package snellv6

import (
	"errors"
	"io"
)

// A physical EOF cannot stand in for Snell's authenticated zero-length record.
// Keeping it distinct prevents reuse of a truncated or closed transport.
func transportReadError(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Only the client response decoder interprets physical EOF as truncation.
// The codec still emits ordinary io.EOF for a complete logical EOF record.
type responseTransportReader struct{ io.Reader }

func (r responseTransportReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	return n, transportReadError(err)
}

func (r responseTransportReader) Upstream() any { return r.Reader }
