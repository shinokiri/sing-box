package snell

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestMobileIdlePolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		android bool
		config  string
		want    *badoption.Duration
	}{
		{"android-passive", true, `{"version":4,"disable_tcp_keep_alive":true}`, common.Ptr(badoption.Duration(60 * time.Second))},
		{"android-explicit-zero", true, `{"version":4,"disable_tcp_keep_alive":true,"tcp_user_timeout":"0s"}`, common.Ptr(badoption.Duration(0))},
		{"android-explicit-value", true, `{"version":4,"disable_tcp_keep_alive":true,"tcp_user_timeout":"120s"}`, common.Ptr(badoption.Duration(120 * time.Second))},
		{"active-keepalive-unchanged", true, `{"version":4}`, nil},
		{"other-platform-unchanged", false, `{"version":4,"disable_tcp_keep_alive":true}`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options option.SnellOutboundOptions
			if err := json.Unmarshal([]byte(test.config), &options); err != nil {
				t.Fatal(err)
			}
			applyMobileIdlePolicy(&options, test.android)
			if test.want == nil {
				if options.TCPUserTimeout != nil {
					t.Fatal("unexpected timeout default")
				}
				return
			}
			if options.TCPUserTimeout == nil || *options.TCPUserTimeout != *test.want {
				t.Fatalf("got %v want %v", options.TCPUserTimeout, test.want)
			}
			if !options.DisableTCPKeepAlive {
				t.Fatal("policy enabled active keepalive")
			}
		})
	}
}
