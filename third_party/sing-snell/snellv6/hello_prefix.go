package snellv6

// Experimental diagnostic codec. It reconstructs the original prefix exactly;
// it does not replace Snell authentication, encryption, salt or record contents.
import (
	"bytes"
	"fmt"
)

type helloPrefixCodec struct {
	template  []byte
	positions []byte
}

func newHelloPrefixCodec(psk []byte) *helloPrefixCodec {
	p := NewProfile(psk)
	saltSize := p.saltBlockLen
	prefixSize := p.recordPrefixLen(0)
	template := make([]byte, saltSize+prefixSize)
	p.fillPadding(0xffffffff, template[:saltSize])
	p.fillPadding(0, template[saltSize:])
	positions := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), saltSize)[:saltLen]
	return &helloPrefixCodec{template: template, positions: positions}
}

func (c *helloPrefixCodec) PrefixSize() int { return len(c.template) }
func (c *helloPrefixCodec) SavedBytes() int { return len(c.template) - len(c.positions) }

func (c *helloPrefixCodec) Pack(original []byte) ([]byte, error) {
	if len(original) < len(c.template) {
		return nil, fmt.Errorf("incomplete original prefix")
	}
	check := append([]byte(nil), original[:len(c.template)]...)
	packed := make([]byte, len(c.positions)+len(original)-len(c.template))
	for i, position := range c.positions {
		packed[i] = original[position]
		check[position] = c.template[position]
	}
	if !bytes.Equal(check, c.template) {
		return nil, fmt.Errorf("original prefix differs from current profile")
	}
	copy(packed[len(c.positions):], original[len(c.template):])
	return packed, nil
}

func (c *helloPrefixCodec) Unpack(packed []byte) ([]byte, error) {
	if len(packed) < len(c.positions) {
		return nil, fmt.Errorf("short packed salt positions")
	}
	out := make([]byte, len(c.template)+len(packed)-len(c.positions))
	copy(out, c.template)
	for i, position := range c.positions {
		out[position] = packed[i]
	}
	copy(out[len(c.template):], packed[len(c.positions):])
	return out, nil
}
