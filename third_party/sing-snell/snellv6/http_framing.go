package snellv6

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
)

// HTTPFraming changes only the first client write. Both endpoints must opt in.
// Reconstructing deterministic profile padding pays for the HTTP header, so the
// kernel can segment normally without reducing the original early-data budget.
// Authentication, ciphertext, salt and record ordering are restored unchanged.
type HTTPFraming struct {
	template  []byte
	positions []byte
	variable  []bool
}

const httpFramingPrefix = "POST / HTTP/1.1\r\nHost: tfo-test.invalid\r\nContent-Length: "

func NewHTTPFraming(psk []byte) (*HTTPFraming, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("snell: HTTP framing requires a PSK")
	}
	profile := NewProfile(psk)
	saltSize := profile.saltBlockLen
	template := make([]byte, saltSize+profile.recordPrefixLen(0))
	profile.fillPadding(0xffffffff, template[:saltSize])
	profile.fillPadding(0, template[saltSize:])
	positions := shufflePerm(profile.namespaces.salt, byte(profile.mixRoundsHandshake), saltSize)[:saltLen]
	// Account for the longest length that fits an int. Configuration errors are
	// rejected before connecting, never hidden by truncation or TCP fallback.
	maxHeader := len(httpFramingPrefix) + len(strconv.Itoa(int(^uint(0)>>1))) + 4
	if len(template)-len(positions) < maxHeader {
		return nil, fmt.Errorf("snell: profile has insufficient recoverable prefix for HTTP framing")
	}
	variable := make([]bool, len(template))
	for _, position := range positions {
		variable[position] = true
	}
	return &HTTPFraming{template: template, positions: positions, variable: variable}, nil
}

func (f *HTTPFraming) Encode(first []byte) ([]byte, error) {
	if len(first) < len(f.template) {
		return nil, fmt.Errorf("snell: incomplete HTTP framing source prefix")
	}
	for i, expected := range f.template {
		if !f.variable[i] && first[i] != expected {
			return nil, fmt.Errorf("snell: HTTP framing source profile mismatch")
		}
	}
	bodyLen := len(first) - len(f.template) + len(f.positions)
	header := httpFramingPrefix + strconv.Itoa(bodyLen) + "\r\n\r\n"
	if len(header)+len(f.positions) > len(f.template) {
		return nil, fmt.Errorf("snell: HTTP framing would reduce early-data capacity")
	}
	wire := make([]byte, len(header)+bodyLen)
	copy(wire, header)
	for i, position := range f.positions {
		wire[len(header)+i] = first[position]
	}
	copy(wire[len(header)+len(f.positions):], first[len(f.template):])
	return wire, nil
}

// DecodePrefix consumes only the header and the variable salt-position bytes.
// The rest of the HTTP body remains in the stream and need not arrive before
// the reconstructed prefix can be passed to Snell or an owned forwarding hop.
func (f *HTTPFraming) DecodePrefix(reader io.Reader) ([]byte, error) {
	prefix := make([]byte, len(httpFramingPrefix))
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, err
	}
	if string(prefix) != httpFramingPrefix {
		return nil, fmt.Errorf("snell: unexpected HTTP framing header")
	}
	var digits [19]byte
	count := 0
	for {
		var one [1]byte
		if _, err := io.ReadFull(reader, one[:]); err != nil {
			return nil, err
		}
		if one[0] == '\r' {
			break
		}
		if one[0] < '0' || one[0] > '9' || count == len(digits) {
			return nil, fmt.Errorf("snell: invalid HTTP framing length")
		}
		digits[count] = one[0]
		count++
	}
	length, err := strconv.ParseUint(string(digits[:count]), 10, 63)
	if err != nil || length < uint64(len(f.positions)) {
		return nil, fmt.Errorf("snell: invalid HTTP framing body length")
	}
	var ending [3]byte
	if _, err = io.ReadFull(reader, ending[:]); err != nil {
		return nil, err
	}
	if string(ending[:]) != "\n\r\n" {
		return nil, fmt.Errorf("snell: invalid HTTP framing terminator")
	}
	var salt [saltLen]byte
	if _, err = io.ReadFull(reader, salt[:]); err != nil {
		return nil, err
	}
	decoded := bytes.Clone(f.template)
	for i, position := range f.positions {
		decoded[position] = salt[i]
	}
	return decoded, nil
}

func (f *HTTPFraming) DecodeConn(conn net.Conn) (net.Conn, error) {
	prefix, err := f.DecodePrefix(conn)
	if err != nil {
		return conn, err
	}
	return bufio.NewCachedConn(conn, buf.As(prefix)), nil
}

type firstHTTPWriter struct {
	upstream io.Writer
	framing  *HTTPFraming
	sent     bool
}

func (w *firstHTTPWriter) Write(p []byte) (int, error) {
	if w.sent || len(p) == 0 {
		return w.upstream.Write(p)
	}
	wire, err := w.framing.Encode(p)
	if err != nil {
		return 0, err
	}
	w.sent = true
	n, err := w.upstream.Write(wire)
	if err != nil {
		return 0, err
	}
	if n != len(wire) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *Client) firstRequestWriter(conn io.Writer) io.Writer {
	if c.httpFraming == nil {
		return conn
	}
	return &firstHTTPWriter{upstream: conn, framing: c.httpFraming}
}

func (c *Client) writeFirstRecord(conn io.Writer, payload []byte) (reuse.RecordWriter, error) {
	writer, err := writeFirstRecord(c.firstRequestWriter(conn), c.mode, c.psk, c.profile, payload)
	if err == nil && c.httpFraming != nil {
		// First-write processing is complete before publishing the record writer.
		// All subsequent scalar and vector writes retain the original fast path.
		writer.(*shapedWriter).upstream = conn
	}
	return writer, err
}

func (c *Client) writeFirstRecordBuffer(conn io.Writer, buffer *buf.Buffer) (reuse.RecordWriter, error) {
	writer, err := writeFirstRecordBuffer(c.firstRequestWriter(conn), c.mode, c.psk, c.profile, buffer)
	if err == nil && c.httpFraming != nil {
		writer.(*shapedWriter).upstream = conn
	}
	return writer, err
}
