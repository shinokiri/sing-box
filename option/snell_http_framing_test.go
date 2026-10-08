package option

import (
	"github.com/sagernet/sing/common/json"
	"testing"
)

func TestSnellHTTPFramingVersionedOption(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		var value any
		if inbound {
			value = new(SnellInboundOptions)
		} else {
			value = new(SnellOutboundOptions)
		}
		if err := json.Unmarshal([]byte(`{"version":6,"psk":"public option fixture","http_framing":true}`), value); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err = json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if fields["http_framing"] != true {
			t.Fatal("versioned option dropped")
		}
	}
	var legacy SnellOutboundOptions
	if err := json.Unmarshal([]byte(`{"version":4,"psk":"public option fixture","http_framing":true}`), &legacy); err == nil {
		t.Fatal("v6 framing option silently accepted for v4")
	}
}
