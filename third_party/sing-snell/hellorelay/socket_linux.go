//go:build linux

package hellorelay

import (
	"golang.org/x/sys/unix"
	"syscall"
)

func socketOption(option, value int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var result error
		err := raw.Control(func(fd uintptr) { result = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, option, value) })
		if err != nil {
			return err
		}
		return result
	}
}

func listenControl(enabled bool, queue int) func(string, string, syscall.RawConn) error {
	if !enabled {
		return nil
	}
	return socketOption(unix.TCP_FASTOPEN, queue)
}

func dialControl(enabled bool) func(string, string, syscall.RawConn) error {
	if !enabled {
		return nil
	}
	return socketOption(unix.TCP_FASTOPEN_CONNECT, 1)
}
