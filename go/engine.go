package tun2socks

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"

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
	mtu         = 1500
	channelSize = 256
	nicID       tcpip.NICID = 1
)

type Engine struct {
	stack     *stack.Stack
	endpoint  *channel.Endpoint
	hook      *EngineHook
	running   atomic.Bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	tunFile   *os.File
	logPrefix string
}

func NewEngine(tunFD int, socksHost string, socksPort int, socksUser, socksPass string, hook *EngineHook) (*Engine, error) {
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

	ep := channel.New(channelSize, mtu, "")

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
		go handleUDPForwarder(r, hook, socksHost, socksPort, socksUser, socksPass)
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
		tunFile:   os.NewFile(uintptr(dupFD), "tun"),
		stopCh:    make(chan struct{}),
		logPrefix: fmt.Sprintf("[teapod-tun2socks fd=%d]", tunFD),
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
	buf := make([]byte, mtu+4)
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, err := e.tunFile.Read(buf)
		if err != nil {
			if e.running.Load() {
				log.Printf("%s TUN read: %v", e.logPrefix, err)
			}
			return
		}
		if n == 0 {
			continue
		}

		pkt := buf[:n]
		var proto tcpip.NetworkProtocolNumber
		switch pkt[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
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

func handleUDPForwarder(req *udp.ForwarderRequest, hook *EngineHook, socksHost string, socksPort int, socksUser, socksPass string) {
	id := req.ID()
	srcIP := net.IP(id.RemoteAddress.AsSlice())
	dstIP := net.IP(id.LocalAddress.AsSlice())
	srcPort := id.RemotePort
	dstPort := id.LocalPort

	if allowed, _ := hook.Validate(srcIP, srcPort, dstIP, dstPort, uint8(ProtocolUDP)); !allowed {
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		return
	}

	gonetConn := gonet.NewUDPConn(&wq, ep)

	socks := NewSOCKS5Client(socksHost, socksPort, socksUser, socksPass)
	assoc, err := socks.UDPAssociate()
	if err != nil {
		gonetConn.Close()
		return
	}

	go pipeUDP(gonetConn, assoc, dstIP, int(dstPort))
}

func pipeUDP(gonetConn *gonet.UDPConn, assoc *UDPAssociation, dstIP net.IP, dstPort int) {
	defer gonetConn.Close()
	defer assoc.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, mtu)
		for {
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

	go func() {
		defer wg.Done()
		buf := make([]byte, mtu+22)
		for {
			n, _, err := assoc.UDPConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _, payload, err := DecodeUDPDatagram(buf[:n])
			if err != nil {
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
	defer left.Close()
	defer right.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(left, right) }()
	go func() { defer wg.Done(); _, _ = io.Copy(right, left) }()
	wg.Wait()
}
