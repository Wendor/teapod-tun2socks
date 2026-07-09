package tun2socks

import (
	"encoding/binary"
)

// buildICMPv4PortUnreachable constructs an ICMPv4 Destination Unreachable / Port Unreachable
// response (Type 3, Code 3) for the given IPv4/UDP packet per RFC 792.
//
// The returned bytes form a complete IPv4 datagram ready to be written to a TUN device:
// the response is addressed FROM the original destination TO the original source, and the
// ICMP body carries the original IP header plus the first 8 bytes (UDP header) so the
// receiving kernel can match the error to the originating socket.
//
// Returns nil if the input is not a well-formed IPv4 UDP packet.
func buildICMPv4PortUnreachable(pkt []byte) []byte {
	if len(pkt) < 28 || pkt[9] != ProtocolUDP {
		return nil
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil
	}

	bodyLen := ihl + 8
	icmpLen := 8 + bodyLen
	icmp := make([]byte, icmpLen)
	icmp[0] = 3 // Destination Unreachable
	icmp[1] = 3 // Port Unreachable
	// icmp[2:4]  checksum — filled in below
	// icmp[4:8]  unused (RFC 792) — already zero
	copy(icmp[8:], pkt[:bodyLen])
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))

	totalLen := 20 + icmpLen
	out := make([]byte, totalLen)
	out[0] = 0x45 // version 4, IHL 5
	// out[1]    TOS = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	// out[4:8]  ID/flags/offset = 0
	out[8] = 64 // TTL
	out[9] = ProtocolICMP
	// out[10:12] checksum below
	copy(out[12:16], pkt[16:20]) // src = orig dst
	copy(out[16:20], pkt[12:16]) // dst = orig src
	binary.BigEndian.PutUint16(out[10:12], internetChecksum(out[:20]))
	copy(out[20:], icmp)
	return out
}

// buildICMPv6PortUnreachable constructs an ICMPv6 Destination Unreachable / Port Unreachable
// response (Type 1, Code 4) per RFC 4443. Assumes the packet has no extension headers
// between the IPv6 base header and the UDP header — the common case for QUIC.
//
// Returns nil if the input is not a well-formed IPv6 UDP packet.
func buildICMPv6PortUnreachable(pkt []byte) []byte {
	if len(pkt) < 48 || pkt[6] != ProtocolUDP {
		return nil
	}

	// Include the IPv6 header + UDP header (48 bytes) in the body. RFC 4443 allows up
	// to MTU-bound truncation; 48 bytes is enough for the kernel to match the socket.
	bodyLen := 48
	if len(pkt) < bodyLen {
		bodyLen = len(pkt)
	}
	icmpLen := 8 + bodyLen
	icmp := make([]byte, icmpLen)
	icmp[0] = 1 // Destination Unreachable
	icmp[1] = 4 // Port Unreachable
	// icmp[2:4]  checksum — below
	// icmp[4:8]  unused
	copy(icmp[8:], pkt[:bodyLen])

	totalLen := 40 + icmpLen
	out := make([]byte, totalLen)
	out[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(out[4:6], uint16(icmpLen))
	out[6] = ProtocolICMPv6
	out[7] = 64 // hop limit
	copy(out[8:24], pkt[24:40])  // src = orig dst
	copy(out[24:40], pkt[8:24])  // dst = orig src

	// ICMPv6 checksum spans a pseudo-header (src + dst + length + next-header) followed
	// by the ICMPv6 message itself.
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(out[8+i])<<8 | uint32(out[8+i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(out[24+i])<<8 | uint32(out[24+i+1])
	}
	sum += uint32(icmpLen)
	sum += uint32(ProtocolICMPv6)
	for i := 0; i+1 < icmpLen; i += 2 {
		sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
	}
	if icmpLen%2 == 1 {
		sum += uint32(icmp[icmpLen-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(icmp[2:4], ^uint16(sum))

	copy(out[40:], icmp)
	return out
}

// internetChecksum computes the standard 16-bit one's-complement Internet checksum
// (RFC 1071) over the given bytes. The caller is expected to zero the checksum field
// of the header being summed prior to calling.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// isUDPDstPortIPv4 reports whether the packet is a well-formed IPv4 UDP datagram
// destined for the given destination port.
func isUDPDstPortIPv4(pkt []byte, port uint16) bool {
	if len(pkt) < 28 || pkt[9] != ProtocolUDP {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+4 {
		return false
	}
	return binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == port
}

// isUDPDstPortIPv6 reports whether the packet is an IPv6 UDP datagram destined for
// the given destination port, walking any extension header chain first.
func isUDPDstPortIPv6(pkt []byte, port uint16) bool {
	proto, off, ok := ipv6TransportHeader(pkt)
	if !ok || proto != ProtocolUDP {
		return false
	}
	if len(pkt) < off+4 {
		return false
	}
	return binary.BigEndian.Uint16(pkt[off+2:off+4]) == port
}

// ipv6TransportHeader walks the IPv6 extension header chain starting at the fixed
// 40-byte base header and returns the upper-layer protocol number and the byte
// offset at which its header begins.
//
// This matters for filtering: reading pkt[6] alone yields the FIRST next-header
// value, which for a packet carrying extension headers (Hop-by-Hop, Routing,
// Destination Options, Fragment) is an extension type, not the transport protocol.
// Without walking the chain, an ICMPv6 echo or QUIC datagram tucked behind a
// Hop-by-Hop header slips past the echo/QUIC filters unexamined.
//
// ok is false for malformed/truncated packets or an unterminated header chain.
func ipv6TransportHeader(pkt []byte) (proto uint8, offset int, ok bool) {
	if len(pkt) < 40 {
		return 0, 0, false
	}
	next := pkt[6]
	off := 40
	// Bound the walk to avoid pathological/looping chains.
	for i := 0; i < 8; i++ {
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(pkt) < off+2 {
				return 0, 0, false
			}
			// Hdr Ext Len is in 8-octet units, not counting the first 8 octets.
			hdrLen := (int(pkt[off+1]) + 1) * 8
			next = pkt[off]
			off += hdrLen
		case 44: // Fragment header — fixed 8 bytes
			if len(pkt) < off+8 {
				return 0, 0, false
			}
			next = pkt[off]
			off += 8
		case 59: // No Next Header
			return 0, 0, false
		default:
			// Upper-layer protocol (TCP, UDP, ICMPv6, ...).
			if off > len(pkt) {
				return 0, 0, false
			}
			return next, off, true
		}
	}
	return 0, 0, false
}
