package main

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func listenTFO(ctx context.Context, address string, queue int) (net.Listener, error) {
	// Preserve the existing relay policy: idle mobile connections generate no keepalive probes.
	config := net.ListenConfig{KeepAlive: -1, Control: func(_, _ string, raw syscall.RawConn) error {
		var optionError error
		if err := raw.Control(func(fd uintptr) {
			optionError = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, queue)
		}); err != nil {
			return err
		}
		return optionError
	}}
	return config.Listen(ctx, "tcp", address)
}
