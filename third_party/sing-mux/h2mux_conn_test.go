package mux

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type responseBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *responseBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestCloseBeforeResponse(t *testing.T) {
	conn := newLateHTTPConn(io.Discard, func() {})
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	body := &responseBody{Reader: strings.NewReader("late response")}
	conn.setup(body, nil)
	if !body.closed.Load() {
		t.Fatal("late response body was not closed")
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the pending reader")
	}
}
