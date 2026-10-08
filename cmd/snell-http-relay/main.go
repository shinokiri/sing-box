// snell-http-relay restores an opt-in Snell v6 first-write frame and forwards
// the original encrypted stream to one configured backend. It is not an HTTP
// forward proxy and does not replace the backend's Snell authentication.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
)

type config struct {
	Listen   string `json:"listen"`
	Upstream string `json:"upstream"`
	PSK      string `json:"psk"`
	TFOQueue int    `json:"tfo_queue"`
}

func main() {
	configPath := flag.String("config", "", "JSON configuration path")
	check := flag.Bool("check", false, "validate configuration without listening")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&cfg)
	file.Close()
	if err != nil {
		log.Fatal("invalid configuration: ", err)
	}
	if cfg.Listen == "" || cfg.Upstream == "" {
		log.Fatal("listen and upstream are required")
	}
	if _, _, err = net.SplitHostPort(cfg.Listen); err != nil {
		log.Fatal("invalid listen address: ", err)
	}
	if _, _, err = net.SplitHostPort(cfg.Upstream); err != nil {
		log.Fatal("invalid upstream address: ", err)
	}
	if cfg.TFOQueue == 0 {
		cfg.TFOQueue = 256
	}
	if cfg.TFOQueue < 1 || cfg.TFOQueue > 65535 {
		log.Fatal("tfo_queue must be between 1 and 65535")
	}
	framing, err := snellv6.NewHTTPFraming([]byte(cfg.PSK))
	if err != nil {
		log.Fatal(err)
	}
	cfg.PSK = ""
	if *check {
		fmt.Println("configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = serve(ctx, cfg, framing); err != nil {
		log.Fatal(err)
	}
}

func serve(ctx context.Context, cfg config, framing *snellv6.HTTPFraming) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := listenTFO(ctx, cfg.Listen, cfg.TFOQueue)
	if err != nil {
		return err
	}
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopListener()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	limit := make(chan struct{}, 8192)
	log.Printf("listening on %s; forwarding to %s", listener.Addr(), cfg.Upstream)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case limit <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-limit }()
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { conn.Close() })
			defer stopConn()
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			prefix, err := framing.DecodePrefix(conn)
			if err != nil {
				return
			}
			conn.SetReadDeadline(time.Time{})
			upstream, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext(ctx, "tcp", cfg.Upstream)
			if err != nil {
				return
			}
			defer upstream.Close()
			stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
			defer stopUpstream()
			n, err := upstream.Write(prefix)
			if err != nil || n != len(prefix) {
				return
			}
			done := make(chan struct{})
			go func() {
				_, err := io.Copy(upstream, conn)
				upstream.(*net.TCPConn).CloseWrite()
				if err != nil {
					upstream.Close()
					conn.Close()
				}
				close(done)
			}()
			_, err = io.Copy(conn, upstream)
			conn.(*net.TCPConn).CloseWrite()
			if err != nil {
				upstream.Close()
				conn.Close()
			}
			<-done
		}()
	}
}
