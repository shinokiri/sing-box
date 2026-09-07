package v2raywebsocket

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/ws"

	"github.com/stretchr/testify/require"
)

func TestCloseInterruptsBlockedIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		conn := NewConn(client, nil, ws.StateClientSide)
		defer client.Close()
		readDone, writeDone := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			readDone <- err
		}()
		go func() {
			_, err := conn.Write([]byte("blocked payload"))
			writeDone <- err
		}()
		synctest.Wait()
		start := time.Now()
		closed := make(chan error, 1)
		go func() { closed <- conn.Close() }()
		synctest.Wait()
		select {
		case err := <-closed:
			require.NoError(t, err)
		default:
			t.Fatal("Close blocked instead of interrupting pending I/O")
		}
		require.Zero(t, time.Since(start), "Close must interrupt I/O without waiting to send a close frame")
		require.Error(t, <-readDone)
		require.Error(t, <-writeDone)
	})
}
