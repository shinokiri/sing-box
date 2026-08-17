package udpflow

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestParseUDPPacketIPv4(t *testing.T) {
	payload := []byte("hello")
	packet := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50000, netip.MustParseAddr("1.1.1.1"), 3478, payload)
	source, destination, parsedPayload, ok := parseUDPPacket(packet)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddrPort("0.0.0.0:50000"), source)
	require.Equal(t, netip.MustParseAddrPort("1.1.1.1:3478"), destination)
	require.Equal(t, payload, parsedPayload)
}

func TestBuildUDPResponseIPv4(t *testing.T) {
	payload := []byte("reply")
	packet, err := buildUDPResponse(8, M.SocksaddrFromNetIP(netip.MustParseAddrPort("1.1.1.1:3478")), 50000, payload)
	require.NoError(t, err)
	source, destination, parsedPayload, ok := parseUDPPacket(packet[8:])
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddrPort("1.1.1.1:3478"), source)
	require.Equal(t, netip.MustParseAddrPort("0.0.0.0:50000"), destination)
	require.Equal(t, payload, parsedPayload)
}

func TestBuildUDPResponseIPv6(t *testing.T) {
	payload := []byte("reply6")
	packet, err := buildUDPResponse(0, M.SocksaddrFromNetIP(netip.MustParseAddrPort("[2001:db8::1]:3478")), 50001, payload)
	require.NoError(t, err)
	source, destination, parsedPayload, ok := parseUDPPacket(packet)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:3478"), source)
	require.Equal(t, netip.MustParseAddrPort("[::]:50001"), destination)
	require.Equal(t, payload, parsedPayload)
}

func buildTestUDPPacket(t *testing.T, source netip.Addr, sourcePort uint16, destination netip.Addr, destinationPort uint16, payload []byte) []byte {
	t.Helper()
	udpLength := header.UDPMinimumSize + len(payload)
	if source.Is4() {
		totalLength := header.IPv4MinimumSize + udpLength
		packet := make([]byte, totalLength)
		ipHdr := header.IPv4(packet)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLength),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     source,
			DstAddr:     destination,
		})
		udpHdr := header.UDP(ipHdr.Payload())
		udpHdr.Encode(&header.UDPFields{SrcPort: sourcePort, DstPort: destinationPort, Length: uint16(udpLength)})
		copy(udpHdr.Payload(), payload)
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(udpLength)),
		)))
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+udpLength)
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLength),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.Encode(&header.UDPFields{SrcPort: sourcePort, DstPort: destinationPort, Length: uint16(udpLength)})
	copy(udpHdr.Payload(), payload)
	udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(udpLength)),
	)))
	return packet
}
