//go:build !linux

package hellorelay

import (
	"fmt"
	"syscall"
)

func dialControl(enabled bool) func(string, string, syscall.RawConn) error {
	if !enabled {
		return nil
	}
	return func(string, string, syscall.RawConn) error { return fmt.Errorf("hello relay: TFO mode requires Linux") }
}

func listenControl(enabled bool, _ int) func(string, string, syscall.RawConn) error {
	return dialControl(enabled)
}
