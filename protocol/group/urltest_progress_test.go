package group

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type progressOutbound struct {
	outbound.Adapter
	started chan<- string
	release <-chan bool
}

func (d *progressOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.started <- d.Tag()
	select {
	case success := <-d.release:
		if !success {
			return nil, errors.New("controlled test failure")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
			fmt.Fprint(server, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}
	}()
	return client, nil
}

func (d *progressOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP")
}

func TestURLTestProgressQueuedNodesAndPartialSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := urltest.NewHistoryStorage()
	started := make(chan string, 21)
	tags := []string{"all"}
	var outbounds []adapter.Outbound
	releases := make(map[string]chan bool)
	for i := 0; i < 21; i++ {
		tag := fmt.Sprintf("node-%02d", i)
		tags = append(tags, tag)
		releases[tag] = make(chan bool, 1)
		outbounds = append(outbounds, &progressOutbound{
			Adapter: outbound.NewAdapter("test", tag, []string{N.NetworkTCP}, nil),
			started: started, release: releases[tag],
		})
		s.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now().Add(-time.Minute), Delay: 123})
	}
	b, _ := s.BeginTestBatch("all", tags)
	testCtx := b.Context(ctx)
	urltest.TestStarted(testCtx, "all")
	go func() {
		URLTestOutbounds(testCtx, nil, s, log.NewNOPFactory().Logger(), outbounds, "http://test.invalid/", 0, true)
		urltest.TestFinished(testCtx, "all", 0, ctx.Err())
		b.Complete()
	}()
	for i := 0; i < 10; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for i, tag := range tags[1:] {
		want := urltest.TestRunning
		if i >= 10 {
			want = urltest.TestQueued
		}
		if s.LoadTestStatus(tag).State != want || s.LoadURLTestHistory(tag).Delay != 123 {
			t.Fatalf("%s: pending state or selection history incorrect", tag)
		}
	}
	releases["node-00"] <- true
	select {
	case <-started: // The newly free slot starts the eleventh node.
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if s.LoadTestStatus("node-00").State != urltest.TestSucceeded || !s.LoadTestStatus("all").Pending() {
		t.Fatal("a refreshed number must not mark the whole round complete")
	}
	if duplicate, owner := s.BeginTestBatch("all", tags); owner || duplicate != b {
		t.Fatal("repeat click started another batch")
	}
	for _, tag := range tags[2:] {
		releases[tag] <- false
	}
	select {
	case <-b.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, tag := range tags[2:] {
		if s.LoadTestStatus(tag).State != urltest.TestFailed || s.LoadURLTestHistory(tag) != nil {
			t.Fatalf("%s retained an old successful result", tag)
		}
	}
}

func TestURLTestProgressWaitsForBackgroundRound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := urltest.NewHistoryStorage()
	started := make(chan string, 2)
	release := make(chan bool, 2)
	d := &progressOutbound{Adapter: outbound.NewAdapter("test", "node", []string{N.NetworkTCP}, nil), started: started, release: release}
	g := &URLTestGroup{history: s, logger: log.NewNOPFactory().Logger(), outbounds: []adapter.Outbound{d}, link: "http://test.invalid/", interruptGroup: interrupt.NewGroup()}
	backgroundDone := make(chan struct{})
	go func() { g.urlTest(ctx, false); close(backgroundDone) }()
	<-started
	b, _ := s.BeginTestBatch("manual", []string{"manual", "node"})
	manualCtx := b.Context(ctx)
	go func() { g.urlTest(manualCtx, true); b.Complete() }()
	select {
	case <-b.Done():
		t.Fatal("busy group falsely acknowledged a completed manual test")
	case <-time.After(20 * time.Millisecond):
	}
	release <- false
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	release <- true
	select {
	case <-b.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	<-backgroundDone
	if s.LoadTestStatus("node").State != urltest.TestSucceeded {
		t.Fatal("manual test never ran after the background test")
	}
}
