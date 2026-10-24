package snellv6

// Experimental diagnostic codec. It reconstructs the original prefix exactly;
// it does not replace Snell authentication, encryption, salt or record contents.
import (
	"bytes"
	"fmt"
	"slices"
)

type helloPrefixCodec struct {
	template  []byte
	positions []byte
	fixed     [][2]int
}

func newHelloPrefixCodec(psk []byte) *helloPrefixCodec {
	p := NewProfile(psk)
	saltSize := p.saltBlockLen
	prefixSize := p.recordPrefixLen(0)
	template := make([]byte, saltSize+prefixSize)
	p.fillPadding(0xffffffff, template[:saltSize])
	p.fillPadding(0, template[saltSize:])
	positions := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), saltSize)[:saltLen]
	// Compare the fixed spans directly instead of copying the whole prefix and
	// overwriting its salt positions on every new connection. Salt order on the
	// wire remains the original permutation, not this sorted validation order.
	sorted := slices.Clone(positions)
	slices.Sort(sorted)
	var fixed [][2]int
	start := 0
	for _, position := range sorted {
		if start < int(position) {
			fixed = append(fixed, [2]int{start, int(position)})
		}
		start = int(position) + 1
	}
	if start < len(template) {
		fixed = append(fixed, [2]int{start, len(template)})
	}
	return &helloPrefixCodec{template: template, positions: positions, fixed: fixed}
}

func (c *helloPrefixCodec) PrefixSize() int { return len(c.template) }
func (c *helloPrefixCodec) SavedBytes() int { return len(c.template) - len(c.positions) }

func (c *helloPrefixCodec) validate(original []byte) error {
	if len(original) < len(c.template) {
		return fmt.Errorf("incomplete original prefix")
	}
	for _, span := range c.fixed {
		if !bytes.Equal(original[span[0]:span[1]], c.template[span[0]:span[1]]) {
			return fmt.Errorf("original prefix differs from current profile")
		}
	}
	return nil
}

// appendSalt is used only after the caller validates the full original prefix.
func (c *helloPrefixCodec) appendSalt(dst, original []byte) []byte {
	for _, position := range c.positions {
		dst = append(dst, original[position])
	}
	return dst
}

func (c *helloPrefixCodec) Pack(original []byte) ([]byte, error) {
	if err := c.validate(original); err != nil {
		return nil, err
	}
	packed := make([]byte, 0, len(c.positions)+len(original)-len(c.template))
	packed = c.appendSalt(packed, original)
	packed = append(packed, original[len(c.template):]...)
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
