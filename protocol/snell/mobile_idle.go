package snell

import (
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

// A mobile client that deliberately disables active keepalive must still learn
// about an expired path when it next sends data. This sets no idle timer and
// sends no probe; explicitly configuring zero preserves the system default.
func applyMobileIdlePolicy(options *option.SnellOutboundOptions, android bool) {
	if !android || !options.DisableTCPKeepAlive || options.TCPUserTimeout != nil {
		return
	}
	options.TCPUserTimeout = common.Ptr(badoption.Duration(60 * time.Second))
}
