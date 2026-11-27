//go:build (linux && !android) || (darwin && !ios)

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

func startEthernetTestStack(t *testing.T, device *MemoryTun, address netip.Prefix) *Go {
	t.Helper()
	t.Cleanup(func() { device.Close() })
	options := Options{MTU: 1500}
	if address.Addr().Is4() {
		options.Inet4Address = []netip.Prefix{address}
	} else {
		options.Inet6Address = []netip.Prefix{address}
	}
	stack, err := NewGo(StackOptions{Context: context.Background(), Tun: device, TunOptions: options, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	return stack
}

func ethernetTestPair(t *testing.T, source netip.Prefix, forward func(header.Ethernet) bool) (client, server *Go, serverTun *MemoryTun) {
	t.Helper()
	clientTun := NewMemoryTun(MemoryTunOptions{MTU: 1500, Ethernet: true, Outbound: func(frames []*buf.Buffer) {
		defer buf.ReleaseMulti(frames)
		for _, frame := range frames {
			if forward(header.Ethernet(frame.Bytes())) {
				serverTun.WaitWritePackets([][]byte{frame.Bytes()})
			}
		}
	}})
	serverTun = NewMemoryTun(MemoryTunOptions{MTU: 1500, Ethernet: true, Outbound: func(frames []*buf.Buffer) {
		defer buf.ReleaseMulti(frames)
		for _, frame := range frames {
			clientTun.WaitWritePackets([][]byte{frame.Bytes()})
		}
	}})
	server = startEthernetTestStack(t, serverTun, netip.PrefixFrom(source.Addr().Next(), source.Bits()))
	client = startEthernetTestStack(t, clientTun, source)
	return client, server, serverTun
}

func ethernetTestNeighborProbe(wire header.Ethernet) bool {
	payload := wire[header.EthernetMinimumSize:]
	switch wire.Type() {
	case goEthernetTypeARP:
		return binary.BigEndian.Uint16(payload[6:]) == goARPRequest
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(payload)
		return ip.NextHeader() == uint8(header.ICMPv6ProtocolNumber) && header.ICMPv6(ip.Payload()).Type() == header.ICMPv6NeighborSolicit
	default:
		return false
	}
}

func TestGoMemoryEthernetLostSolicitation(t *testing.T) {
	for _, source := range []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24"), netip.MustParsePrefix("fd73:5a1e::1/64")} {
		t.Run(source.Addr().String(), func(t *testing.T) {
			t.Parallel()
			var probes atomic.Int32
			client, server, _ := ethernetTestPair(t, source, func(wire header.Ethernet) bool {
				return !ethernetTestNeighborProbe(wire) || probes.Add(1) > 1
			})
			address := netip.AddrPortFrom(source.Addr().Next(), 12345)
			listener, err := server.ListenTCP(address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			// A SYN sent on the wire would back off until 3 s on its second retry.
			// Learning a missing link address must wake the first actual SYN.
			ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
			defer cancel()
			conn, err := client.DialTCP(ctx, source.Addr(), address)
			if err != nil {
				t.Fatalf("dial after dropping the first of %d neighbor probes: %v", probes.Load(), err)
			}
			defer conn.Close()
			if probes.Load() < 2 {
				t.Fatalf("got %d neighbor probes", probes.Load())
			}
			listener.SetDeadline(time.Now().Add(3 * time.Second))
			accepted, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			accepted.Close()
		})
	}
}

func TestGoMemoryEthernetCanceledDial(t *testing.T) {
	source := netip.MustParsePrefix("198.18.0.1/24")
	canceled := netip.AddrPortFrom(source.Addr().Next(), 12345)
	active := netip.AddrPortFrom(canceled.Addr(), canceled.Port()+1)
	held := make(chan []byte, 1)
	var staleSYN atomic.Bool
	client, server, serverTun := ethernetTestPair(t, source, func(wire header.Ethernet) bool {
		if ethernetTestNeighborProbe(wire) {
			select {
			case held <- bytes.Clone(wire):
			default:
			}
			return false
		}
		if wire.Type() == header.IPv4ProtocolNumber {
			ip := header.IPv4(wire[header.EthernetMinimumSize:])
			if ip.Protocol() == uint8(header.TCPProtocolNumber) {
				tcp := header.TCP(ip.Payload())
				if tcp.DestinationPort() == canceled.Port() && tcp.Flags()&header.TCPFlagSyn != 0 {
					staleSYN.Store(true)
				}
			}
		}
		return true
	})
	listener, err := server.ListenTCP(active)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialTCP(ctx, source.Addr(), canceled)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	var request []byte
	select {
	case request = <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("missing ARP request")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled dial returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not honor cancellation")
	}
	if err := serverTun.WaitWritePackets([][]byte{request}); err != nil {
		t.Fatal(err)
	}
	activeCtx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	conn, err := client.DialTCP(activeCtx, source.Addr(), active)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if staleSYN.Load() {
		t.Fatal("learning the peer emitted a SYN for the canceled dial")
	}
}
