//go:build linux && !android

package tun

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	kernelConnectionRefused = unix.ECONNREFUSED
	kernelConnectionReset   = unix.ECONNRESET
)

func kernelSetSocketBuffers(descriptor uintptr, size int) error {
	return E.Errors(
		unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, size),
		unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_SNDBUF, size),
	)
}

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	link, err := netlink.LinkByName(options.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range append(options.Inet4Address, options.Inet6Address...) {
		address, parseErr := netlink.ParseAddr(prefix.String())
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		address.Flags = unix.IFA_F_NODAD
		err = netlink.AddrAdd(link, address)
		if err != nil {
			t.Fatal(err)
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range options.Inet6Address {
		if err := kernelWaitIPv6LocalRoute(prefix.Addr()); err != nil {
			t.Fatal(err)
		}
	}
}

func kernelWaitIPv6LocalRoute(address netip.Addr) error {
	deadline := time.Now().Add(time.Second)
	for {
		routes, err := netlink.RouteGet(address.AsSlice())
		if err != nil && !errors.Is(err, unix.ENETUNREACH) {
			return err
		}
		if len(routes) > 0 && routes[0].Type == unix.RTN_LOCAL {
			return nil
		}
		if time.Now().After(deadline) {
			return E.New("IPv6 local route was not installed: ", address)
		}
		time.Sleep(time.Millisecond)
	}
}
