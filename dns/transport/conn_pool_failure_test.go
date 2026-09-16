package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnPoolFailedDialContextCleanup(t *testing.T) {
	for _, mode := range []ConnPoolMode{ConnPoolSingle, ConnPoolOrdered} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			pool := newContextTestPool(mode)
			defer pool.Close()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			dialFailure := errors.New("dial failed")
			for attempt := 0; attempt < 64; attempt++ {
				contexts := make(chan context.Context, 1)
				_, _, err := pool.Acquire(parent, func(ctx context.Context) (*poolContextConn, error) {
					contexts <- ctx
					return nil, dialFailure
				})
				if !errors.Is(err, dialFailure) {
					t.Fatalf("attempt %d: unexpected error %v", attempt, err)
				}
				dialCtx := <-contexts
				select {
				case <-dialCtx.Done():
				case <-time.After(time.Second):
					t.Fatalf("attempt %d retained its failed dial context", attempt)
				}
			}
			// Cleanup must not depend on cancellation of the caller or pool.
			if parent.Err() != nil {
				t.Fatal("the parent was canceled before cleanup was checked")
			}
		})
	}
}

func TestConnPoolLateDialContextCleanup(t *testing.T) {
	for _, mode := range []ConnPoolMode{ConnPoolSingle, ConnPoolOrdered} {
		for _, retire := range []string{"close", "reset", "request_cancel"} {
			t.Run(fmt.Sprintf("mode_%d/%s", mode, retire), func(t *testing.T) {
				closed := make(chan *poolContextConn, 2)
				pool := NewConnPool(ConnPoolOptions[*poolContextConn]{
					Mode:    mode,
					IsAlive: func(c *poolContextConn) bool { return !c.closed.Load() },
					Close: func(c *poolContextConn, _ error) {
						c.closed.Store(true)
						closed <- c
					},
				})
				defer pool.Close()
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				started := make(chan *poolContextConn, 1)
				finished := make(chan error, 1)
				allowReturn := make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(allowReturn) }) }
				defer release()
				var calls atomic.Int32
				go func() {
					_, _, err := pool.Acquire(parent, func(ctx context.Context) (*poolContextConn, error) {
						if calls.Add(1) != 1 {
							return nil, errors.New("new state dial")
						}
						conn := &poolContextConn{ctx: ctx}
						started <- conn
						// Simulate a dial finishing successfully after cancellation.
						<-allowReturn
						return conn, nil
					})
					finished <- err
				}()
				var conn *poolContextConn
				select {
				case conn = <-started:
				case <-time.After(time.Second):
					t.Fatal("dial did not start")
				}
				switch retire {
				case "close":
					pool.Close()
				case "reset":
					pool.Reset()
				case "request_cancel":
					cancel()
				}
				select {
				case <-conn.ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("pending dial ignored cancellation")
				}
				release()
				select {
				case got := <-closed:
					if got != conn || !conn.closed.Load() {
						t.Fatal("the late connection was not closed")
					}
				case <-time.After(time.Second):
					t.Fatal("the late connection was orphaned")
				}
				select {
				case err := <-finished:
					if err == nil {
						t.Fatal("acquire accepted a canceled connection")
					}
				case <-time.After(time.Second):
					t.Fatal("acquire did not exit")
				}
			})
		}
	}
}
