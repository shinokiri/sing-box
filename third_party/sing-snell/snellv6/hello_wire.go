package snellv6

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

func helloRecord(payload []byte, compactRecord bool) ([]byte, error) {
	if len(payload) < 1 || len(payload) > 4096 {
		return nil, fmt.Errorf("carrier payload out of bounds")
	}
	// The envelope is fixed except for lengths, random and the carrier kind.
	// Fill one final allocation instead of building extensions and copying them
	// through a body buffer before constructing the same wire representation.
	out := make([]byte, 85+len(payload))
	copy(out, []byte{22, 3, 1})
	binary.BigEndian.PutUint16(out[3:5], uint16(len(out)-5))
	out[5] = 1
	binary.BigEndian.PutUint16(out[7:9], uint16(len(out)-9))
	copy(out[9:11], []byte{3, 3})
	if _, err := rand.Read(out[11:43]); err != nil {
		return nil, err
	}
	copy(out[43:50], []byte{0, 0, 2, 0x13, 1, 1, 0})
	binary.BigEndian.PutUint16(out[50:52], uint16(len(out)-52))
	copy(out[52:81], []byte{
		0, 43, 0, 3, 2, 3, 4,
		0, 10, 0, 4, 0, 2, 0, 29,
		0, 13, 0, 4, 0, 2, 8, 7,
		0, 51, 0, 2, 0, 0,
	})
	var carrierType uint16 = 0xffaa
	if compactRecord {
		carrierType = 0xffab
	}
	binary.BigEndian.PutUint16(out[81:83], carrierType)
	binary.BigEndian.PutUint16(out[83:85], uint16(len(payload)))
	copy(out[85:], payload)
	return out, nil
}

func helloPayload(record []byte) ([]byte, error) {
	if len(record) < 86 || len(record) > 4181 || !bytes.Equal(record[:3], []byte{22, 3, 1}) || int(binary.BigEndian.Uint16(record[3:]))+5 != len(record) || record[5] != 1 || record[6] != 0 || int(binary.BigEndian.Uint16(record[7:]))+9 != len(record) {
		return nil, fmt.Errorf("invalid carrier record")
	}
	if !bytes.Equal(record[43:52], []byte{0, 0, 2, 0x13, 1, 1, 0, byte((len(record) - 52) >> 8), byte(len(record) - 52)}) {
		return nil, fmt.Errorf("invalid carrier parameters")
	}
	seen := map[uint16]bool{}
	var payload []byte
	for at := 52; at < len(record); {
		if at+4 > len(record) {
			return nil, fmt.Errorf("short extension")
		}
		kind := binary.BigEndian.Uint16(record[at:])
		size := int(binary.BigEndian.Uint16(record[at+2:]))
		at += 4
		if seen[kind] || at+size > len(record) {
			return nil, fmt.Errorf("invalid extension")
		}
		seen[kind] = true
		if kind == 0xffaa || kind == 0xffab {
			if payload != nil {
				return nil, fmt.Errorf("multiple carrier extensions")
			}
			payload = record[at : at+size]
		}
		at += size
	}
	if len(payload) < 16 {
		return nil, fmt.Errorf("missing packed prefix")
	}
	return payload, nil
}

// Called only after helloPayload has validated all extension boundaries.
func helloHasRecordCodec(wire []byte) bool {
	for at := 52; at < len(wire); {
		kind := binary.BigEndian.Uint16(wire[at:])
		size := int(binary.BigEndian.Uint16(wire[at+2:]))
		at += 4
		if kind == 0xffab {
			return true
		}
		at += size
	}
	return false
}

// DecodeHello restores the original Snell stream prefix. The caller forwards
// these bytes first, followed by the unread remainder of the same connection.
func (t *HelloTransport) DecodeHello(reader io.Reader) ([]byte, error) {
	_, packed, err := readHelloFrame(reader)
	if err != nil {
		return nil, err
	}
	return t.codec.Unpack(packed)
}

// ReadHelloFrame validates and reads exactly one private carrier without
// consuming any following stream bytes. It does not authenticate the Snell
// payload; a pass-through relay can use it without the landing's PSK.
func ReadHelloFrame(reader io.Reader) ([]byte, error) {
	wire, _, err := readHelloFrame(reader)
	return wire, err
}

func readHelloFrame(reader io.Reader) ([]byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length < 81 || length > 4176 {
		return nil, nil, fmt.Errorf("snell: hello length out of bounds")
	}
	wire := make([]byte, 5+length)
	copy(wire, header)
	if _, err := io.ReadFull(reader, wire[5:]); err != nil {
		return nil, nil, err
	}
	packed, err := helloPayload(wire)
	if err != nil {
		return nil, nil, err
	}
	if !helloHasRecordCodec(wire) {
		return nil, nil, fmt.Errorf("snell: unsupported hello encoding")
	}
	return wire, packed, nil
}
