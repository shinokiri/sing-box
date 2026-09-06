package v2ray

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type handshakeTestDialer struct {
	N.Dialer
	conn net.Conn
}

func TestWebsocketKeepsSubprotocolAcrossDials(t *testing.T) {
	dialer := &handshakeTestDialer{}
	client, err := NewClientTransport(context.Background(), dialer, M.ParseSocksaddr("localhost:443"), option.V2RayTransportOptions{
		Type: "ws",
		WebsocketOptions: option.V2RayWebsocketOptions{Headers: badoption.HTTPHeader{
			"Sec-WebSocket-Protocol": {"udpflow-test"},
		}},
	}, nil)
	require.NoError(t, err)
	defer client.Close()
	for range 2 {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		dialer.conn = clientConn
		done := make(chan error, 1)
		go func() {
			conn, err := client.DialContext(context.Background())
			if conn != nil {
				conn.Close()
			}
			done <- err
		}()
		require.NoError(t, serverConn.SetDeadline(time.Now().Add(time.Second)))
		request, err := http.ReadRequest(bufio.NewReader(serverConn))
		require.NoError(t, err)
		request.Body.Close()
		require.Equal(t, "udpflow-test", request.Header.Get("Sec-WebSocket-Protocol"))
		_, err = serverConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		require.NoError(t, err)
		select {
		case err := <-done:
			require.Error(t, err)
		case <-time.After(time.Second):
			t.Fatal("rejected WebSocket upgrade did not finish")
		}
	}
}

func (d *handshakeTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func TestUpgradeHandshakeCancellation(t *testing.T) {
	for _, transportType := range []string{"ws", "httpupgrade"} {
		t.Run(transportType, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			client, err := NewClientTransport(context.Background(), &handshakeTestDialer{conn: clientConn}, M.ParseSocksaddr("localhost:443"), option.V2RayTransportOptions{Type: transportType}, nil)
			require.NoError(t, err)
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := client.DialContext(ctx)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(time.Second)))
			request, err := http.ReadRequest(bufio.NewReader(serverConn))
			require.NoError(t, err)
			request.Body.Close()
			// The peer reads the upgrade request but never sends its response.
			cancel()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("canceling the dial did not interrupt the upgrade handshake")
			}
		})
	}
}
