package socks

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

/*
In the sock implementation of * ray, UDP authentication is flawed and can be bypassed.
Tracking a UDP connection may be a bit troublesome.
Here is a simple solution.
We create a filter, add remote IP to the pool when it try to establish a UDP connection with auth.
And drop UDP packets from unauthorized IP.
After discussion, we believe it is not necessary to add a timeout mechanism to this filter.
*/

type UDPFilter struct {
	ips          sync.Map
	ttl          time.Duration
	now          func() time.Time
	cleanupEvery uint32
	operations   atomic.Uint32
}

const (
	defaultUDPFilterTTL      = 10 * time.Minute
	defaultUDPCleanupEveryOp = 128
)

func NewUDPFilter(ttl time.Duration) *UDPFilter {
	if ttl <= 0 {
		ttl = defaultUDPFilterTTL
	}
	return &UDPFilter{
		ttl:          ttl,
		now:          time.Now,
		cleanupEvery: defaultUDPCleanupEveryOp,
	}
}

func ipFromAddr(addr net.Addr) (string, bool) {
	if addr == nil {
		return "", false
	}
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil || ip == "" {
		return "", false
	}
	return ip, true
}

func (f *UDPFilter) maybeCleanup(now time.Time) {
	if f.cleanupEvery == 0 {
		return
	}
	if f.operations.Add(1)%f.cleanupEvery != 0 {
		return
	}
	nowUnix := now.UnixNano()
	f.ips.Range(func(key, value any) bool {
		expireAt, ok := value.(int64)
		if !ok || expireAt <= nowUnix {
			f.ips.Delete(key)
		}
		return true
	})
}

func (f *UDPFilter) Add(addr net.Addr) bool {
	ip, ok := ipFromAddr(addr)
	if !ok {
		return false
	}
	now := f.now()
	f.ips.Store(ip, now.Add(f.ttl).UnixNano())
	f.maybeCleanup(now)
	return true
}

func (f *UDPFilter) Check(addr net.Addr) bool {
	ip, ok := ipFromAddr(addr)
	if !ok {
		return false
	}
	now := f.now()
	value, exists := f.ips.Load(ip)
	if !exists {
		f.maybeCleanup(now)
		return false
	}
	expireAt, ok := value.(int64)
	if !ok || expireAt <= now.UnixNano() {
		f.ips.Delete(ip)
		f.maybeCleanup(now)
		return false
	}
	// Sliding expiration keeps active authenticated UDP sessions alive.
	f.ips.Store(ip, now.Add(f.ttl).UnixNano())
	f.maybeCleanup(now)
	return true
}
