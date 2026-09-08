package mux

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closeCountingConn struct {
	net.Conn
	calls atomic.Int32
	err   error
}

func (c *closeCountingConn) Close() error { c.calls.Add(1); return c.err }

func TestH2MuxServerConcurrentClose(t *testing.T) {
	closeErr := errors.New("transport close")
	for round := 0; round < 32; round++ {
		conn := &closeCountingConn{err: closeErr}
		s := &h2MuxServerSession{conn: conn, inbound: make(chan net.Conn), done: make(chan struct{})}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < 16; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				if err := s.Close(); !errors.Is(err, closeErr) {
					t.Errorf("close: %v", err)
				}
			}()
		}
		close(start)
		workers.Wait()
		if conn.calls.Load() != 1 {
			t.Fatalf("transport closed %d times", conn.calls.Load())
		}
		if !s.IsClosed() {
			t.Fatal("session is still open")
		}
		if _, err := s.Accept(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("accept after close: %v", err)
		}
	}
}

type readyResponseWriter struct {
	*httptest.ResponseRecorder
	ready chan struct{}
}

func (w *readyResponseWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	close(w.ready)
}

func TestH2MuxServerCloseUnblocksPendingAccept(t *testing.T) {
	s := &h2MuxServerSession{conn: &closeCountingConn{}, inbound: make(chan net.Conn), done: make(chan struct{})}
	body := &responseBody{Reader: strings.NewReader("unused")}
	w := &readyResponseWriter{httptest.NewRecorder(), make(chan struct{})}
	returned := make(chan struct{})
	go func() {
		s.ServeHTTP(w, httptest.NewRequest(http.MethodConnect, "https://localhost", body))
		close(returned)
	}()
	<-w.ready
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("session close left the HTTP handler waiting for Accept")
	}
	if !body.closed.Load() {
		t.Fatal("unaccepted stream body was not closed")
	}
	if s.NumStreams() != 0 {
		t.Fatal("closed stream is still active")
	}
}
