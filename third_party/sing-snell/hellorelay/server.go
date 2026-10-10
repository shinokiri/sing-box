// Package hellorelay forwards the private Snell hello carrier. It does not
// implement TLS, multiplex streams, or modify system network configuration.
package hellorelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
)

type Mode string

const (
	PassThrough Mode = "pass"
	Decode      Mode = "decode"
)

type Options struct {
	Mode           Mode
	Upstream       string
	PSK            []byte
	ListenTFO      bool
	UpstreamTFO    bool
	TFOQueue       int
	SetupTimeout   time.Duration
	DialTimeout    time.Duration
	MaxConnections int
}

type Stats struct {
	Accepted  uint64 `json:"accepted"`
	Rejected  uint64 `json:"rejected"`
	Completed uint64 `json:"completed"`
	Failed    uint64 `json:"failed"`
	Active    int    `json:"active"`
}

type Server struct {
	opts      Options
	decoder   *snellv6.HelloTransport
	dial      func(context.Context, string, string) (net.Conn, error)
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	listener  net.Listener
	started   bool
	closed    bool
	sessions  map[*session]struct{}
	wg        sync.WaitGroup
	accepted  atomic.Uint64
	rejected  atomic.Uint64
	completed atomic.Uint64
	failed    atomic.Uint64
}

type session struct {
	client   net.Conn
	mu       sync.Mutex
	upstream net.Conn
	closed   bool
}

func (c *session) attach(up net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		up.Close()
		return false
	}
	c.upstream = up
	return true
}

func (c *session) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	up := c.upstream
	c.mu.Unlock()
	c.client.Close()
	if up != nil {
		up.Close()
	}
}

func New(options Options) (*Server, error) {
	if options.Mode != PassThrough && options.Mode != Decode {
		return nil, fmt.Errorf("hello relay: mode must be pass or decode")
	}
	host, port, err := net.SplitHostPort(options.Upstream)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("hello relay: upstream must be host:numeric-port (1..65535)")
	}
	if options.SetupTimeout == 0 {
		options.SetupTimeout = 5 * time.Second
	}
	if options.DialTimeout == 0 {
		options.DialTimeout = 4 * time.Second
	}
	if options.MaxConnections == 0 {
		options.MaxConnections = 256
	}
	if options.TFOQueue == 0 {
		options.TFOQueue = 128
	}
	if options.SetupTimeout < 0 || options.DialTimeout < 0 || options.MaxConnections < 1 || options.MaxConnections > 65536 || options.TFOQueue < 1 || options.TFOQueue > 65535 {
		return nil, fmt.Errorf("hello relay: invalid timeout or connection limit")
	}
	var decoder *snellv6.HelloTransport
	if options.Mode == Decode {
		decoder, err = snellv6.NewHelloTransport(options.PSK)
		if err != nil {
			return nil, err
		}
	} else if len(options.PSK) != 0 {
		return nil, fmt.Errorf("hello relay: pass mode does not use a PSK")
	}
	// Decoder owns its key; do not retain another copy in Options.
	options.PSK = nil
	ctx, cancel := context.WithCancel(context.Background())
	dialer := net.Dialer{Timeout: options.DialTimeout, Control: dialControl(options.UpstreamTFO), KeepAliveConfig: keepAlive()}
	return &Server{opts: options, decoder: decoder, dial: dialer.DialContext, ctx: ctx, cancel: cancel, sessions: make(map[*session]struct{})}, nil
}

func keepAlive() net.KeepAliveConfig {
	return net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}
}

// Listen opens only this listener's TFO queue. No global sysctl is changed.
func (s *Server) Listen(address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: listenControl(s.opts.ListenTFO, s.opts.TFOQueue), KeepAliveConfig: keepAlive()}
	return lc.Listen(s.ctx, "tcp", address)
}

// Serve owns listener and all accepted connections. One Server has one Serve.
func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	s.started = true
	s.listener = listener
	s.mu.Unlock()
	defer s.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.accepted.Add(1)
		c := &session{client: conn}
		s.mu.Lock()
		if s.closed || len(s.sessions) >= s.opts.MaxConnections {
			s.mu.Unlock()
			conn.Close()
			s.rejected.Add(1)
			continue
		}
		s.sessions[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			err := s.handle(c)
			c.close()
			s.mu.Lock()
			delete(s.sessions, c)
			s.mu.Unlock()
			if err != nil {
				s.failed.Add(1)
			} else {
				s.completed.Add(1)
			}
		}()
	}
}

func (s *Server) handle(c *session) error {
	deadline := time.Now().Add(s.opts.SetupTimeout)
	setup, cancel := context.WithDeadline(s.ctx, deadline)
	defer cancel()
	stopTimeout := context.AfterFunc(setup, c.close)
	defer stopTimeout()
	if err := c.client.SetDeadline(deadline); err != nil {
		return err
	}
	if tcp, ok := c.client.(*net.TCPConn); ok {
		if err := tcp.SetNoDelay(true); err != nil {
			return err
		}
	}
	var prefix []byte
	var err error
	if s.decoder == nil {
		prefix, err = snellv6.ReadHelloFrame(c.client)
	} else {
		prefix, err = s.decoder.DecodeHello(c.client)
	}
	if err != nil {
		return fmt.Errorf("read initial carrier: %w", err)
	}
	up, err := s.dial(setup, "tcp", s.opts.Upstream)
	if err != nil {
		return fmt.Errorf("connect upstream: %w", err)
	}
	if !c.attach(up) {
		return net.ErrClosed
	}
	if tcp, ok := up.(*net.TCPConn); ok {
		if err := tcp.SetNoDelay(true); err != nil {
			return err
		}
	}
	if err := up.SetDeadline(deadline); err != nil {
		return err
	}
	if n, err := up.Write(prefix); err != nil {
		return fmt.Errorf("forward initial carrier: %w", err)
	} else if n != len(prefix) {
		return io.ErrShortWrite
	}
	prefix = nil
	// The setup limit must not become a lifetime limit. Stop the callback
	// before canceling setup, then remove both socket deadlines.
	stopped := stopTimeout()
	if err := setup.Err(); err != nil {
		return err
	}
	if !stopped {
		return context.DeadlineExceeded
	}
	cancel()
	if err := c.client.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := up.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return copyBoth(c, up)
}

func copyBoth(c *session, up net.Conn) error {
	results := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = fmt.Errorf("hello relay: destination lacks TCP half-close")
			}
		}
		if err != nil {
			c.close()
		}
		results <- err
	}
	go copyOne(up, c.client)
	go copyOne(c.client, up)
	return errors.Join(<-results, <-results)
}

func (s *Server) Snapshot() Stats {
	s.mu.Lock()
	active := len(s.sessions)
	s.mu.Unlock()
	return Stats{Accepted: s.accepted.Load(), Rejected: s.rejected.Load(), Completed: s.completed.Load(), Failed: s.failed.Load(), Active: active}
}

// Close stops accepts, cancels pending setup/dial work, interrupts both copy
// directions and waits for accepted sessions to release their resources.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	listener := s.listener
	var sessions []*session
	for c := range s.sessions {
		sessions = append(sessions, c)
	}
	s.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
	for _, c := range sessions {
		c.close()
	}
	s.wg.Wait()
	return nil
}
