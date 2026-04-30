package tun2socks

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"golang.org/x/sys/unix"
)

const (
	channelSize = 256
	nicID        tcpip.NICID = 1
	// udpIdleTimeout is the maximum idle time for a UDP flow before its goroutines
	// and sockets are released. The deadline is reset on every received packet, so
	// active sessions (QUIC, gaming) stay alive indefinitely; only truly idle flows
	// (finished DNS queries, stale connections) are cleaned up.
	udpIdleTimeout = 60 * time.Second
	// tcpIdleTimeout is the maximum idle time for a TCP flow. The deadline is reset
	// on every received chunk, so active transfers (streaming, downloads) are unaffected.
	// Stuck connections (e.g. after an LTE tower handover with no FIN/RST) are cleaned up
	// before they fill the gVisor TCP forwarder backlog (limit: 1024).
	tcpIdleTimeout = 5 * time.Minute
)

type Engine struct {
	stack     *stack.Stack
	endpoint  *channel.Endpoint
	hook      *EngineHook
	mtu       int
	running   atomic.Bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	tunFile    *os.File
	logPrefix  string
	allowICMP  bool
	txBytes   atomic.Uint64
	rxBytes   atomic.Uint64
}

func NewEngine(tunFD int, mtu int, socksHost string, socksPort int, socksUser, socksPass string, allowICMP bool, hook *EngineHook) (*Engine, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: false,
	})

	ep := channel.New(channelSize, uint32(mtu), "")

	if tcpipErr := s.CreateNIC(nicID, ep); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	tcpForwarder := tcp.NewForwarder(s, 65535, 1024, func(r *tcp.ForwarderRequest) {
		go handleTCPForwarder(r, hook, socksHost, socksPort, socksUser, socksPass)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		srcIP := net.IP(id.RemoteAddress.AsSlice())
		dstIP := net.IP(id.LocalAddress.AsSlice())
		
		if allowed, _ := hook.Validate(srcIP, id.RemotePort, dstIP, id.LocalPort, uint8(ProtocolUDP)); !allowed {
			return false 
		}
		
		go handleUDPForwarder(r, hook, socksHost, socksPort, socksUser, socksPass, mtu)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	dupFD, err := unix.Dup(tunFD)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("dup tunFD: %v", err)
	}
	unix.CloseOnExec(dupFD)

	return &Engine{
		stack:     s,
		endpoint:  ep,
		hook:      hook,
		mtu:       mtu,
		tunFile:   os.NewFile(uintptr(dupFD), "tun"),
		stopCh:    make(chan struct{}),
		logPrefix: fmt.Sprintf("[teapod-tun2socks fd=%d mtu=%d]", tunFD, mtu),
		allowICMP:  allowICMP,
	}, nil
}

func (e *Engine) Start() error {
	if !e.running.CompareAndSwap(false, true) {
		return fmt.Errorf("engine already running")
	}
	log.Printf("%s engine started", e.logPrefix)

	ctx, cancel := context.WithCancel(context.Background())

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.tunReadLoop()
	}()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.tunWriteLoop(ctx)
	}()

	<-e.stopCh
	cancel()
	log.Printf("%s engine stopped", e.logPrefix)
	return nil
}

func (e *Engine) tunReadLoop() {
	buf := make([]byte, e.mtu+4)
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, err := e.tunFile.Read(buf)
		if err != nil {
			if e.running.Load() {
				// TUN fd was closed externally (e.g. Android revoked VPN during a phone call
				// without calling onRevoke). Trigger Stop() so IsRunning() returns false,
				// which the Kotlin heartbeat detects and uses to trigger a reconnect.
				log.Printf("%s TUN read error — fd closed externally, triggering stop: %v", e.logPrefix, err)
				go e.Stop() // must be async: Stop calls wg.Wait which would deadlock if called directly
			}
			return
		}
		if n == 0 {
			continue
		}
		e.txBytes.Add(uint64(n))

		pkt := buf[:n]
		var proto tcpip.NetworkProtocolNumber
		switch pkt[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
			// Filter ICMPv4 echo packets when allowICMP is disabled.
			// ICMP has no source ports, so per-app UID lookup is not possible;
			// the filter applies to all apps uniformly.
			if !e.allowICMP && len(pkt) > 9 && pkt[9] == ProtocolICMP {
				if shouldBlockICMP(pkt, false) {
					log.Printf("%s ICMPv4 blocked (echo)", e.logPrefix)
					continue
				}
			}
		case 6:
			proto = header.IPv6ProtocolNumber
			// Filter ICMPv6 echo packets when allowICMP is disabled.
			if !e.allowICMP && len(pkt) > 6 {
				nextHeader := pkt[6]
				if nextHeader == ProtocolICMPv6 && shouldBlockICMP(pkt, true) {
					log.Printf("%s ICMPv6 blocked (echo)", e.logPrefix)
					continue
				}
			}
		default:
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		e.endpoint.InjectInbound(proto, pkb)
		pkb.DecRef()
	}
}

// shouldBlockICMP checks if an ICMP packet should be blocked.
// For IPv4, ICMP header starts after the IP header (IHL * 4 bytes).
// For IPv6, ICMP header starts after the fixed 40-byte IPv6 header.
// Blocks Echo Request (type 8/128) and Echo Reply (type 0/129) to prevent
// unauthorized apps from using ping to bypass application filters.
// Allows all other ICMP types (error messages like Destination Unreachable, etc.)
func shouldBlockICMP(pkt []byte, isIPv6 bool) bool {
	var icmpTypeOffset int
	if isIPv6 {
		if len(pkt) < 40 {
			return true // Malformed packet
		}
		icmpTypeOffset = 40 // ICMPv6 header starts after fixed IPv6 header
	} else {
		if len(pkt) < 20 {
			return true // Malformed packet
		}
		// IPv4 IHL is in bits 4-7 of byte 0, in 32-bit words
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl+1 {
			return true // Malformed packet
		}
		icmpTypeOffset = ihl
	}

	if len(pkt) <= icmpTypeOffset {
		return true
	}

	icmpType := pkt[icmpTypeOffset]
	// Block Echo Request and Echo Reply for both IPv4 and IPv6
	// IPv4: Echo Request = 8, Echo Reply = 0
	// IPv6: Echo Request = 128, Echo Reply = 129
	if icmpType == 0 || icmpType == 8 || icmpType == 128 || icmpType == 129 {
		return true
	}
	return false
}

func (e *Engine) tunWriteLoop(ctx context.Context) {
	for {
		pkt := e.endpoint.ReadContext(ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		data := v.AsSlice()
		if _, err := e.tunFile.Write(data); err != nil && e.running.Load() {
			log.Printf("%s TUN write: %v", e.logPrefix, err)
		} else {
			e.rxBytes.Add(uint64(len(data)))
		}
		v.Release()
		pkt.DecRef()
	}
}

func (e *Engine) Stop() {
	if !e.running.CompareAndSwap(true, false) {
		return
	}
	close(e.stopCh)
	e.tunFile.Close()
	e.stack.Close()
	e.wg.Wait()
	log.Printf("%s engine shut down complete", e.logPrefix)
}

func (e *Engine) IsRunning() bool { return e.running.Load() }

func handleTCPForwarder(req *tcp.ForwarderRequest, hook *EngineHook, socksHost string, socksPort int, socksUser, socksPass string) {
	id := req.ID()
	// gVisor Forwarder: 
	// RemoteAddress is the Source (Phone).
	// LocalAddress is the Destination (Internet).
	srcIP := net.IP(id.RemoteAddress.AsSlice())
	dstIP := net.IP(id.LocalAddress.AsSlice())
	srcPort := id.RemotePort
	dstPort := id.LocalPort

	if allowed, _ := hook.Validate(srcIP, srcPort, dstIP, dstPort, uint8(ProtocolTCP)); !allowed {
		req.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		req.Complete(true)
		return
	}

	ep.SocketOptions().SetKeepAlive(false)
	gonetConn := gonet.NewTCPConn(&wq, ep)

	proxyConn, dialErr := NewSOCKS5Client(socksHost, socksPort, socksUser, socksPass).
		DialTCP(dstIP.String(), int(dstPort))
	if dialErr != nil {
		gonetConn.Close()
		return
	}

	go pipeConnections(gonetConn, proxyConn)
}

func handleUDPForwarder(req *udp.ForwarderRequest, hook *EngineHook, socksHost string, socksPort int, socksUser, socksPass string, mtu int) {
	id := req.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice())
	dstPort := id.LocalPort

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		return
	}

	gonetConn := gonet.NewUDPConn(&wq, ep)

	socks := NewSOCKS5Client(socksHost, socksPort, socksUser, socksPass)
	assoc, err := socks.UDPAssociate()
	if err != nil {
		log.Printf("[teapod-tun2socks] UDP ASSOCIATE failed for %s:%d: %v", dstIP, dstPort, err)
		gonetConn.Close()
		return
	}

	go pipeUDP(gonetConn, assoc, dstIP, int(dstPort), mtu)
}

func pipeUDP(gonetConn *gonet.UDPConn, assoc *UDPAssociation, dstIP net.IP, dstPort int, mtu int) {
	// shutdown closes both ends exactly once, unblocking whichever goroutine is
	// still blocked on a read. Each goroutine calls defer shutdown() so that when
	// either side exits (error, idle timeout, or upstream close) the other side is
	// guaranteed to unblock and exit immediately.
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			gonetConn.Close()
			assoc.Close()
		})
	}
	defer shutdown()

	var wg sync.WaitGroup
	wg.Add(2)

	// TUN -> relay: read from gVisor endpoint, forward to SOCKS5 UDP relay.
	go func() {
		defer wg.Done()
		defer shutdown()
		buf := make([]byte, mtu)
		for {
			// Idle-based deadline: reset before every read so the timeout only fires
			// when no packet has arrived for udpIdleTimeout, not after an absolute time.
			gonetConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := gonetConn.Read(buf)
			if err != nil {
				return
			}
			datagram := EncodeUDPDatagram(dstIP, dstPort, buf[:n])
			if _, err := assoc.UDPConn.WriteToUDP(datagram, assoc.RelayAddr); err != nil {
				return
			}
		}
	}()

	// relay -> TUN: read responses from SOCKS5 UDP relay, forward to gVisor endpoint.
	go func() {
		defer wg.Done()
		defer shutdown()
		buf := make([]byte, mtu+22)
		for {
			assoc.UDPConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, _, err := assoc.UDPConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _, payload, err := DecodeUDPDatagram(buf[:n])
			if err != nil {
				log.Printf("[teapod-tun2socks] UDP datagram dropped: %v", err)
				continue
			}
			if _, err := gonetConn.Write(payload); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func pipeConnections(left, right net.Conn) {
	// shutdown closes both ends exactly once, unblocking whichever goroutine is
	// still blocked on a read — same pattern as pipeUDP.
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			left.Close()
			right.Close()
		})
	}
	defer shutdown()

	var wg sync.WaitGroup
	wg.Add(2)

	// pipe copies src → dst with an idle-based deadline that resets on every chunk.
	// This ensures stuck connections (no FIN/RST after a network change) are cleaned
	// up within tcpIdleTimeout, preventing the gVisor forwarder backlog from filling.
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		defer shutdown()
		buf := make([]byte, 32*1024)
		for {
			src.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go pipe(right, left)
	go pipe(left, right)
	wg.Wait()
}
