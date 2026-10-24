package snell

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// net/http may finish TLS cleanup asynchronously after its HEAD response has
// returned. A closed logical connection must not change the deadline of the
// physical session now reserved for the next request.
func TestURLTestClosedRequestCannotChangeNextDeadline(t *testing.T) {
	for _, kind := range []string{"write", "read", "both"} {
		t.Run(kind, func(t *testing.T) {
			node, transport := newURLTestFixture(t, &urlTestHandler{})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dialer, closer, err := node.NewURLTestDialer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			first, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("probe.test:80"))
			if err != nil {
				t.Fatal(err)
			}
			request204(t, first)
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			second, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("probe.test:80"))
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			expired := time.Now().Add(-time.Second)
			switch kind {
			case "write":
				err = first.SetWriteDeadline(expired)
			case "read":
				err = first.SetReadDeadline(expired)
			default:
				err = first.SetDeadline(expired)
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("closed logical deadline returned %v, want net.ErrClosed", err)
			}
			request204(t, second)
			if transport.dials.Load() != 1 {
				t.Fatal("second request opened a replacement physical connection")
			}
		})
	}
}

func TestURLTestClosedRequestCannotWriteIntoNextRequest(t *testing.T) {
	node, transport := newURLTestFixture(t, &urlTestHandler{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer, closer, err := node.NewURLTestDialer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	first, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("probe.test:80"))
	if err != nil {
		t.Fatal(err)
	}
	request204(t, first)
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("probe.test:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	// A late TLS close_notify is application data from the old logical stream.
	done := make(chan error, 1)
	go func() { _, err := first.Write([]byte("late TLS close_notify")); done <- err }()
	select {
	case err = <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late write returned %v, want net.ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("late write blocked instead of rejecting a closed request")
	}
	request204(t, second)
	if transport.dials.Load() != 1 {
		t.Fatal("next request redialed")
	}
}

func request204(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := io.WriteString(conn, "HEAD /generate_204 HTTP/1.1\r\nHost: probe.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodHead})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("HTTP status %d", response.StatusCode)
	}
}
