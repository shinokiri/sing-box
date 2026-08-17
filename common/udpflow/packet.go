package udpflow

import (
	"math"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const udpFlowHopLimit = 64

func parseUDPPacket(packet []byte) (source netip.AddrPort, destination netip.AddrPort, payload []byte, ok bool) {
	var transport []byte
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.More() || ipHdr.FragmentOffset() != 0 || ipHdr.TransportProtocol() != header.UDPProtocolNumber {
			return
		}
		source = netip.AddrPortFrom(ipHdr.SourceAddr(), 0)
		destination = netip.AddrPortFrom(ipHdr.DestinationAddr(), 0)
		transport = ipHdr.Payload()
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return
		}
		protocol, nextPayload, fragmented, present := skipUDPIPv6ExtensionHeaders(uint8(ipHdr.TransportProtocol()), ipHdr.Payload())
		if fragmented || !present || protocol != uint8(header.UDPProtocolNumber) {
			return
		}
		source = netip.AddrPortFrom(ipHdr.SourceAddr(), 0)
		destination = netip.AddrPortFrom(ipHdr.DestinationAddr(), 0)
		transport = nextPayload
	default:
		return
	}
	if len(transport) < header.UDPMinimumSize {
		return
	}
	udpHdr := header.UDP(transport)
	udpLength := int(udpHdr.Length())
	if udpLength < header.UDPMinimumSize || udpLength > len(transport) {
		return
	}
	source = netip.AddrPortFrom(source.Addr(), udpHdr.SourcePort())
	destination = netip.AddrPortFrom(destination.Addr(), udpHdr.DestinationPort())
	payload = transport[header.UDPMinimumSize:udpLength]
	ok = true
	return
}

func skipUDPIPv6ExtensionHeaders(protocol uint8, payload []byte) (uint8, []byte, bool, bool) {
	for {
		switch header.IPv6ExtensionHeaderIdentifier(protocol) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
			if len(payload) < 2 {
				return protocol, payload, false, false
			}
			extensionLength := (int(payload[1]) + 1) * 8
			if len(payload) < extensionLength {
				return protocol, payload, false, false
			}
			protocol = payload[0]
			payload = payload[extensionLength:]
		case header.IPv6FragmentExtHdrIdentifier:
			return protocol, payload, true, false
		default:
			return protocol, payload, false, true
		}
	}
}

func buildUDPResponse(headroom int, source M.Socksaddr, selector uint16, payload []byte) ([]byte, error) {
	source = source.Unwrap()
	sourceAddr := source.Addr.Unmap()
	if !sourceAddr.IsValid() || source.Port == 0 {
		return nil, E.New("invalid UDP response source: ", source)
	}
	udpLength := header.UDPMinimumSize + len(payload)
	if udpLength > math.MaxUint16 {
		return nil, E.New("UDP response payload too large: ", len(payload))
	}
	var (
		packet []byte
		udpHdr header.UDP
		ipHdr  header.Network
	)
	if sourceAddr.Is4() {
		totalLength := header.IPv4MinimumSize + udpLength
		if totalLength > math.MaxUint16 {
			return nil, E.New("IPv4 UDP response too large: ", len(payload))
		}
		packet = make([]byte, headroom+totalLength)
		inet4Hdr := header.IPv4(packet[headroom:])
		inet4Hdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLength),
			TTL:         udpFlowHopLimit,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     sourceAddr,
			DstAddr:     netip.IPv4Unspecified(),
		})
		udpHdr = header.UDP(inet4Hdr.Payload())
		ipHdr = inet4Hdr
	} else {
		packet = make([]byte, headroom+header.IPv6MinimumSize+udpLength)
		inet6Hdr := header.IPv6(packet[headroom:])
		inet6Hdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLength),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          udpFlowHopLimit,
			SrcAddr:           sourceAddr,
			DstAddr:           netip.IPv6Unspecified(),
		})
		udpHdr = header.UDP(inet6Hdr.Payload())
		ipHdr = inet6Hdr
	}
	udpHdr.Encode(&header.UDPFields{
		SrcPort: source.Port,
		DstPort: selector,
		Length:  uint16(udpLength),
	})
	copy(udpHdr.Payload(), payload)
	udpChecksum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(udpLength)),
	))
	if udpChecksum == 0 {
		udpChecksum = math.MaxUint16
	}
	udpHdr.SetChecksum(udpChecksum)
	if inet4Hdr, isIPv4 := ipHdr.(header.IPv4); isIPv4 {
		inet4Hdr.SetChecksum(^inet4Hdr.CalculateChecksum())
	}
	return packet, nil
}
