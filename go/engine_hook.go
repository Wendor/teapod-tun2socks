package tun2socks

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UIDValidatorFunc is the Kotlin callback invoked for each new connection.
//
// gomobile limitation: interface methods may return at most one primitive value.
// Validate returns true if the connection should be forwarded, false to block it.
// The Kotlin side already knows the UID when it answers, so UID is not returned here.
type UIDValidatorFunc interface {
	// Validate is called for every new TCP/UDP connection.
	// Returns true to allow, false to deny.
	//   srcIP, srcPort — source address
	//   dstIP, dstPort — destination address
	//   protocol       — 6 (TCP) or 17 (UDP)
	Validate(srcIP string, srcPort int, dstIP string, dstPort int, protocol int) bool
}

// EngineHook ties the LRU cache together with the UID validator callback.
type EngineHook struct {
	cache      *LRUCache
	// udpSrcCache caches UDP validation by (srcIP, srcPort) only.
	// Telegram and other QUIC apps open many UDP flows from one socket (same srcPort)
	// to different CDN servers. Without this cache every new dst triggers a synchronous
	// Kotlin IPC call (getConnectionOwnerUid), blocking tunReadLoop for each one.
	// The UID is determined by the source socket, not the destination, so caching by
	// src alone is correct for UDP.
	udpSrcCache *LRUCache
	validator   UIDValidatorFunc
	mu          sync.RWMutex
	logEnabled  atomic.Bool
}

// NewEngineHook creates a new hook.
// capacity — max entries in the LRU cache
// ttlSeconds — TTL for cached entries in seconds
func NewEngineHook(capacity int, ttlSeconds int) *EngineHook {
	ttl := time.Duration(ttlSeconds) * time.Second
	h := &EngineHook{
		cache:       NewLRUCache(capacity, ttl),
		udpSrcCache: NewLRUCache(capacity, ttl),
	}
	h.logEnabled.Store(true)
	return h
}

// SetValidator sets the Kotlin callback.
func (h *EngineHook) SetValidator(v UIDValidatorFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.validator = v
}

// udpSrcKey returns a cache key containing only the UDP source — used as a secondary
// cache so that flows from the same socket to different destinations share one IPC call.
func udpSrcKey(srcIP net.IP, srcPort uint16) ConnectionKey {
	return ConnectionKey{SrcIP: srcIP.String(), SrcPort: srcPort, Proto: ProtocolUDP}
}

// Validate checks the cache first; on miss, calls the Kotlin validator.
// For UDP an additional src-only cache is consulted before the IPC call to avoid
// per-destination IPC overhead when one app socket reaches many remote endpoints.
func (h *EngineHook) Validate(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, proto uint8) (bool, int) {
	key := NewConnectionKey(srcIP, srcPort, dstIP, dstPort, proto)

	if result, ok := h.cache.Get(key); ok {
		if h.logEnabled.Load() {
			log.Printf("[teapod-tun2socks] cache HIT %s — allowed=%v", key, result.Allowed)
		}
		return result.Allowed, result.UID
	}

	// For UDP, check the src-only cache before calling Kotlin IPC.
	// One app UDP socket (same srcPort) connects to many remote addresses; the UID
	// is determined by the socket, not the destination.
	if proto == ProtocolUDP {
		sk := udpSrcKey(srcIP, srcPort)
		if result, ok := h.udpSrcCache.Get(sk); ok {
			if h.logEnabled.Load() {
				log.Printf("[teapod-tun2socks] udpSrcCache HIT %s — allowed=%v", key, result.Allowed)
			}
			h.cache.Add(key, result)
			return result.Allowed, result.UID
		}
	}

	h.mu.RLock()
	validator := h.validator
	h.mu.RUnlock()

	if validator == nil {
		log.Printf("[teapod-tun2socks] WARNING: no validator set, DENYING %s", key)
		return false, -1
	}

	allowed := validator.Validate(
		srcIP.String(), int(srcPort),
		dstIP.String(), int(dstPort),
		int(proto),
	)

	if h.logEnabled.Load() {
		log.Printf("[teapod-tun2socks] cache MISS %s — allowed=%v (from Kotlin)", key, allowed)
	}

	result := ValidationResult{Allowed: allowed, UID: -1}
	h.cache.Add(key, result)
	if proto == ProtocolUDP {
		h.udpSrcCache.Add(udpSrcKey(srcIP, srcPort), result)
	}
	return allowed, -1
}

// Invalidate removes a connection from the cache.
func (h *EngineHook) Invalidate(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, proto uint8) {
	h.cache.Remove(NewConnectionKey(srcIP, srcPort, dstIP, dstPort, proto))
	if proto == ProtocolUDP {
		h.udpSrcCache.Remove(udpSrcKey(srcIP, srcPort))
	}
}

// CacheLen returns the current full-cache size.
func (h *EngineHook) CacheLen() int { return h.cache.Len() }

// SetLogEnabled toggles internal logging.
func (h *EngineHook) SetLogEnabled(enabled bool) { h.logEnabled.Store(enabled) }
