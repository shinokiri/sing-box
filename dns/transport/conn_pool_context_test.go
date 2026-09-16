package transport

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type poolContextConn struct {
	ctx    context.Context
	closed atomic.Bool
}

func newContextTestPool(mode ConnPoolMode) *ConnPool[*poolContextConn] {
	return NewConnPool(ConnPoolOptions[*poolContextConn]{
		Mode:    mode,
		IsAlive: func(c *poolContextConn) bool { return !c.closed.Load() },
		Close:   func(c *poolContextConn, _ error) { c.closed.Store(true) },
	})
}

func TestConnPoolDialContextRetirement(t *testing.T) {
	for _, mode := range []ConnPoolMode{ConnPoolSingle, ConnPoolOrdered} {
		for _, retire := range []string{"close", "reset", "invalidate", "release", "dead", "idle"} {
			if mode == ConnPoolOrdered && retire == "idle" {
				continue
			}
			t.Run(fmt.Sprintf("mode_%d/%s", mode, retire), func(t *testing.T) {
				pool := newContextTestPool(mode)
				defer pool.Close()
				conn, created, err := pool.Acquire(context.Background(), func(ctx context.Context) (*poolContextConn, error) {
					return &poolContextConn{ctx: ctx}, nil
				})
				if err != nil || !created {
					t.Fatalf("acquire: created=%v error=%v", created, err)
				}
				if err := conn.ctx.Err(); err != nil {
					t.Fatalf("dial context ended before first write: %v", err)
				}
				switch retire {
				case "close":
					pool.Close()
				case "reset":
					pool.Reset()
				case "invalidate":
					pool.Invalidate(conn, errors.New("broken connection"))
				case "release":
					pool.Release(conn, false)
				case "idle":
					pool.Release(conn, true)
					pool.CloseIdle()
				case "dead":
					pool.Release(conn, true)
					conn.closed.Store(true)
					_, _, err = pool.Acquire(context.Background(), func(ctx context.Context) (*poolContextConn, error) {
						return &poolContextConn{ctx: ctx}, nil
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-conn.ctx.Done():
				default:
					t.Fatal("retired connection retained its dial context")
				}
				if !conn.closed.Load() {
					t.Fatal("retired connection was not closed")
				}
			})
		}
	}
}

func TestConnPoolResetCancelsPendingDial(t *testing.T) {
	for _, mode := range []ConnPoolMode{ConnPoolSingle, ConnPoolOrdered} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			pool := newContextTestPool(mode)
			defer pool.Close()
			started := make(chan context.Context, 1)
			finished := make(chan error, 1)
			go func() {
				_, _, err := pool.Acquire(context.Background(), func(ctx context.Context) (*poolContextConn, error) {
					started <- ctx
					<-ctx.Done()
					return nil, ctx.Err()
				})
				finished <- err
			}()
			var dialCtx context.Context
			select {
			case dialCtx = <-started:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			pool.Reset()
			select {
			case <-dialCtx.Done():
			case <-time.After(time.Second):
				t.Fatal("reset left pending dial running")
			}
			pool.Close()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("acquire did not exit after reset and close")
			}
		})
	}
}
