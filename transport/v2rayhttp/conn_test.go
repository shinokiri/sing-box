package v2rayhttp

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLateHTTPConnCloseBeforeSetup(t *testing.T) {
	conn := NewLateHTTPConn(io.Discard)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	require.NoError(t, conn.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("closing before the HTTP response did not unblock the read")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	conn.Setup(reader, nil)
	go func() {
		_, err := writer.Write([]byte("late response"))
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, io.ErrClosedPipe, "a late response body must be closed")
	case <-time.After(time.Second):
		t.Fatal("late response body was left open")
	}
	require.NoError(t, conn.Close())
}

func TestLateHTTPConnSetupPublishesReader(t *testing.T) {
	conn := NewLateHTTPConn(io.Discard)
	defer conn.Close()
	done := make(chan error, 1)
	buffer := make([]byte, 1)
	go func() {
		_, err := io.ReadFull(conn, buffer)
		done <- err
	}()
	conn.Setup(strings.NewReader("x"), nil)
	select {
	case err := <-done:
		require.NoError(t, err)
		require.Equal(t, []byte("x"), buffer)
	case <-time.After(time.Second):
		t.Fatal("the initialized response reader did not become available")
	}
}
