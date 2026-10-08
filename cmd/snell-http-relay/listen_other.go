//go:build !linux

package main

import (
	"context"
	"fmt"
	"net"
)

func listenTFO(context.Context, string, int) (net.Listener, error) {
	return nil, fmt.Errorf("snell-http-relay requires Linux TCP Fast Open")
}
