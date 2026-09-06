//go:build with_quic

package v2rayquic

import (
	"context"
	stdTLS "crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type testDialer struct {
	N.Dialer
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d *testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, destination)
}

func newTestClient(t *testing.T, ctx context.Context, dialer N.Dialer, address string, options option.OutboundTLSOptions) *Client {
	t.Helper()
	config, err := tls.NewSTDClient(ctx, logger.NOP(), "localhost", options)
	require.NoError(t, err)
	transport, err := NewClient(ctx, dialer, M.ParseSocksaddr(address), option.V2RayQUICOptions{}, config)
	require.NoError(t, err)
	return transport.(*Client)
}

func testResult[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for QUIC test event")
		var zero T
		return zero
	}
}

func TestQUICDialCancellation(t *testing.T) {
	for _, waiter := range []bool{false, true} {
		name := "dial"
		if waiter {
			name = "waiting-for-shared-dial"
		}
		t.Run(name, func(t *testing.T) {
			parent, stopParent := context.WithCancel(context.Background())
			started := make(chan struct{}, 2)
			var calls atomic.Int32
			client := newTestClient(t, parent, &testDialer{dial: func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
				calls.Add(1)
				started <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}}, "127.0.0.1:443", option.OutboundTLSOptions{})
			t.Cleanup(func() {
				stopParent()
				client.Close()
			})
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			first := make(chan error, 1)
			go func() {
				_, err := client.DialContext(ctx)
				first <- err
			}()
			testResult(t, started)
			if waiter {
				waiting, stopWaiting := context.WithTimeout(parent, 20*time.Millisecond)
				defer stopWaiting()
				second := make(chan error, 1)
				go func() {
					_, err := client.DialContext(waiting)
					second <- err
				}()
				require.ErrorIs(t, testResult(t, second), context.DeadlineExceeded)
				require.Equal(t, int32(1), calls.Load(), "a canceled waiter must not start another dial")
			}
			cancel()
			require.ErrorIs(t, testResult(t, first), context.Canceled)
		})
	}
}

func TestQUICHandshakeCancellation(t *testing.T) {
	parent, stopParent := context.WithCancel(context.Background())
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client := newTestClient(t, parent, &testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, destination.String())
	}}, listener.LocalAddr().String(), option.OutboundTLSOptions{})
	t.Cleanup(func() {
		stopParent()
		client.Close()
	})
	started := make(chan error, 1)
	go func() {
		_, _, err := listener.ReadFrom(make([]byte, 2048))
		started <- err
	}()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.DialContext(ctx)
		done <- err
	}()
	require.NoError(t, testResult(t, started))
	cancel()
	require.ErrorIs(t, testResult(t, done), context.Canceled)
}

func TestQUICEstablishedConnectionSurvivesDialCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	certificate, err := tls.GenerateKeyPair(nil, nil, time.Now, "localhost")
	require.NoError(t, err)
	listener, err := quic.ListenAddr("127.0.0.1:0", &stdTLS.Config{
		Certificates: []stdTLS.Certificate{*certificate},
		NextProtos:   []string{"udpflow-test"},
	}, nil)
	require.NoError(t, err)
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.CloseWithError(0, "")
		for range 2 {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				serverResult <- err
				return
			}
			payload := make([]byte, 1)
			if _, err = io.ReadFull(stream, payload); err == nil {
				_, err = stream.Write(payload)
			}
			stream.Close()
			if err != nil {
				serverResult <- err
				return
			}
		}
		serverResult <- nil
		<-ctx.Done()
	}()
	var detourContext context.Context
	client := newTestClient(t, ctx, &testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, destination.String())
		if err != nil {
			return nil, err
		}
		// Streaming detours such as gRPC keep using the context passed to
		// the UDP dialer after DialContext returns.
		detourContext = ctx
		context.AfterFunc(ctx, func() { conn.Close() })
		return conn, nil
	}}, listener.Addr().String(), option.OutboundTLSOptions{
		ALPN:        []string{"udpflow-test"},
		Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))},
	})
	defer client.Close()
	for index := range 2 {
		dialCtx, stopDial := context.WithTimeout(ctx, time.Second)
		conn, err := client.DialContext(dialCtx)
		stopDial()
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
		_, err = conn.Write([]byte{byte(index)})
		require.NoError(t, err)
		payload := make([]byte, 1)
		_, err = io.ReadFull(conn, payload)
		require.NoError(t, err)
		require.Equal(t, []byte{byte(index)}, payload)
		require.NoError(t, conn.Close())
	}
	require.NoError(t, testResult(t, serverResult))
	require.NoError(t, client.Close())
	select {
	case <-detourContext.Done():
	case <-time.After(time.Second):
		t.Fatal("closing the QUIC client did not release its detour context")
	}
}
