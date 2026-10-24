// snell-hello is a standalone receiver for the private Snell hello carrier.
// It is not a TLS server and never changes firewall rules or global sysctls.
package main

import (
	"bytes"
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
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sagernet/sing-snell/hellorelay"
)

type config struct {
	Listen         string          `json:"listen"`
	Upstream       string          `json:"upstream"`
	Mode           hellorelay.Mode `json:"mode"`
	PSKFile        string          `json:"psk_file,omitempty"`
	ListenTFO      bool            `json:"listen_tfo"`
	UpstreamTFO    bool            `json:"upstream_tfo"`
	TFOQueue       int             `json:"tfo_queue,omitempty"`
	SetupTimeout   string          `json:"setup_timeout,omitempty"`
	DialTimeout    string          `json:"dial_timeout,omitempty"`
	MaxConnections int             `json:"max_connections,omitempty"`
}

func readConfig(path string) (config, hellorelay.Options, error) {
	var cfg config
	var opts hellorelay.Options
	f, err := os.Open(path)
	if err != nil {
		return cfg, opts, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return cfg, opts, fmt.Errorf("read config: %w", err)
	}
	if len(data) > 65536 {
		return cfg, opts, fmt.Errorf("config exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, opts, fmt.Errorf("read config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return cfg, opts, fmt.Errorf("config must contain exactly one JSON object")
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	p, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || p < 1 || p > 65535 {
		return cfg, opts, fmt.Errorf("listen must be host:numeric-port (1..65535)")
	}
	opts = hellorelay.Options{Mode: cfg.Mode, Upstream: cfg.Upstream, ListenTFO: cfg.ListenTFO, UpstreamTFO: cfg.UpstreamTFO, TFOQueue: cfg.TFOQueue, MaxConnections: cfg.MaxConnections}
	parse := func(value string, target *time.Duration) error {
		if value == "" {
			return nil
		}
		d, e := time.ParseDuration(value)
		if e != nil || d <= 0 {
			return fmt.Errorf("timeouts must be positive Go durations")
		}
		*target = d
		return nil
	}
	if err := parse(cfg.SetupTimeout, &opts.SetupTimeout); err != nil {
		return cfg, opts, err
	}
	if err := parse(cfg.DialTimeout, &opts.DialTimeout); err != nil {
		return cfg, opts, err
	}
	if cfg.Mode == hellorelay.PassThrough && cfg.PSKFile != "" {
		return cfg, opts, fmt.Errorf("pass mode must not have a psk_file")
	}
	if cfg.Mode == hellorelay.Decode {
		if cfg.PSKFile == "" {
			return cfg, opts, fmt.Errorf("decode mode requires psk_file")
		}
		keyPath := cfg.PSKFile
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(filepath.Dir(path), keyPath)
		}
		keyFile, err := os.Open(keyPath)
		if err != nil {
			return cfg, opts, fmt.Errorf("open psk_file: %w", err)
		}
		key, readErr := io.ReadAll(io.LimitReader(keyFile, 258))
		keyFile.Close()
		if readErr != nil {
			return cfg, opts, fmt.Errorf("read psk_file: %w", readErr)
		}
		// Accept one optional line ending, preserving all other key bytes.
		key = bytes.TrimSuffix(key, []byte("\n"))
		key = bytes.TrimSuffix(key, []byte("\r"))
		if len(key) < 12 || len(key) > 255 || bytes.ContainsAny(key, "\r\n") {
			return cfg, opts, fmt.Errorf("psk_file must contain one 12..255 byte key")
		}
		opts.PSK = key
	}
	return cfg, opts, nil
}

func serve(ctx context.Context, server *hellorelay.Server, address string, logger *log.Logger) error {
	listener, err := server.Listen(address)
	if err != nil {
		return err
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	logger.Printf("ready listen=%s", listener.Addr())
	select {
	case err = <-done:
	case <-ctx.Done():
		server.Close()
		err = <-done
	}
	stats, _ := json.Marshal(server.Snapshot())
	logger.Printf("stopped stats=%s", stats)
	return err
}

func main() {
	configPath := flag.String("config", "", "JSON configuration file (required)")
	check := flag.Bool("check", false, "validate configuration without opening sockets")
	flag.Parse()
	logger := log.New(os.Stderr, "snell-hello: ", log.LstdFlags|log.LUTC)
	if *configPath == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	cfg, options, err := readConfig(*configPath)
	if err != nil {
		logger.Print(err)
		os.Exit(1)
	}
	server, err := hellorelay.New(options)
	clear(options.PSK)
	if err != nil {
		logger.Print(err)
		os.Exit(1)
	}
	if *check {
		server.Close()
		logger.Print("configuration valid; no sockets opened")
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := serve(ctx, server, cfg.Listen, logger); err != nil {
		logger.Print(err)
		os.Exit(1)
	}
}
