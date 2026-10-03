package v2raygrpclite

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGunConnLargeDeclaredLength(t *testing.T) {
	frame := binary.AppendUvarint(make([]byte, 6), math.MaxUint64)
	frame = append(frame, "abc"...)
	conn := newGunConn(bytes.NewReader(frame), io.Discard, nil)
	defer conn.Close()
	for _, expected := range []byte("abc") {
		payload := make([]byte, 1)
		n, err := conn.Read(payload)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Equal(t, expected, payload[0])
	}
	_, err := conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestLateGunConnCloseBeforeSetup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := newLateGunConn(io.Discard, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	require.NoError(t, conn.Close())
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("closing before the HTTP response did not unblock the read")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	conn.setup(reader, nil)
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

func TestLateGunConnSetupPublishesReader(t *testing.T) {
	conn := newLateGunConn(io.Discard, nil)
	defer conn.Close()
	done := make(chan error, 1)
	buffer := make([]byte, 1)
	go func() {
		_, err := io.ReadFull(conn, buffer)
		done <- err
	}()
	conn.setup(strings.NewReader("\x00\x00\x00\x00\x03\x0a\x01x"), nil)
	select {
	case err := <-done:
		require.NoError(t, err)
		require.Equal(t, []byte("x"), buffer)
	case <-time.After(time.Second):
		t.Fatal("the initialized response reader did not become available")
	}
}
