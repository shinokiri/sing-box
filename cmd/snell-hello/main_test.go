package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-snell/hellorelay"
)

func TestConfigValidationAndKeyFile(t *testing.T) {
	dir := t.TempDir()
	key := []byte(" public-config-fixture-key ")
	if err := os.WriteFile(filepath.Join(dir, "key"), append(append([]byte(nil), key...), '\r', '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	for _, tc := range []struct {
		name, text string
		valid      bool
	}{
		{"pass", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"pass","listen_tfo":true,"upstream_tfo":true}`, true},
		{"decode_relative_key", `{"listen":"127.0.0.1:30814","upstream":"127.0.0.1:17468","mode":"decode","psk_file":"key","setup_timeout":"2s"}`, true},
		{"unknown", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"pass","typo":true}`, false},
		{"trailing_object", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"pass"} {}`, false},
		{"negative_timeout", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"pass","setup_timeout":"-1s"}`, false},
		{"unknown_mode", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"other"}`, false},
		{"missing_key", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"decode"}`, false},
		{"unused_key", `{"listen":"[::]:30813","upstream":"192.0.2.1:30814","mode":"pass","psk_file":"key"}`, false},
		{"bad_port", `{"listen":"[::]:30813","upstream":"192.0.2.1:70000","mode":"pass"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, options, err := readConfig(path)
			if err == nil {
				var server *hellorelay.Server
				server, err = hellorelay.New(options)
				if err == nil {
					server.Close()
				}
				if cfg.Mode == hellorelay.Decode && !bytes.Equal(options.PSK, key) {
					t.Fatal("key bytes were changed")
				}
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
