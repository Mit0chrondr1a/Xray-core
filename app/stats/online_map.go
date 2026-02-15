package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// OnlineMap is an implementation of stats.OnlineMap.
type OnlineMap struct {
	ipList        map[string]time.Time
	access        sync.RWMutex
	lastCleanup   time.Time
	cleanupPeriod time.Duration
	cleaning      atomic.Bool // trylock to prevent redundant concurrent cleanups
}

// NewOnlineMap creates a new instance of OnlineMap.
func NewOnlineMap() *OnlineMap {
	return &OnlineMap{
		ipList:        make(map[string]time.Time),
		lastCleanup:   time.Now(),
		cleanupPeriod: 10 * time.Second,
	}
}

// Count implements stats.OnlineMap.
func (c *OnlineMap) Count() int {
	c.access.RLock()
	defer c.access.RUnlock()

	return len(c.ipList)
}

// List implements stats.OnlineMap.
func (c *OnlineMap) List() []string {
	return c.GetKeys()
}

// AddIP implements stats.OnlineMap.
func (c *OnlineMap) AddIP(ip string) {
	if ip == "127.0.0.1" {
		return
	}
	needsCleanup := false
	c.access.Lock()
	c.ipList[ip] = time.Now()
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		needsCleanup = true
	}
	c.access.Unlock()
	if needsCleanup && c.cleaning.CompareAndSwap(false, true) {
		c.RemoveExpiredIPs()
		c.access.Lock()
		c.lastCleanup = time.Now()
		c.access.Unlock()
		c.cleaning.Store(false)
	}
}

func (c *OnlineMap) GetKeys() []string {
	c.access.RLock()
	defer c.access.RUnlock()

	keys := make([]string, 0, len(c.ipList))
	for k := range c.ipList {
		keys = append(keys, k)
	}
	return keys
}

func (c *OnlineMap) RemoveExpiredIPs() {
	c.access.Lock()
	defer c.access.Unlock()

	now := time.Now()
	for k, t := range c.ipList {
		diff := now.Sub(t)
		if diff.Seconds() > 20 {
			delete(c.ipList, k)
		}
	}
}

func (c *OnlineMap) IpTimeMap() map[string]time.Time {
	needsCleanup := false
	c.access.RLock()
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		needsCleanup = true
	}
	c.access.RUnlock()
	if needsCleanup && c.cleaning.CompareAndSwap(false, true) {
		c.RemoveExpiredIPs()
		c.access.Lock()
		c.lastCleanup = time.Now()
		c.access.Unlock()
		c.cleaning.Store(false)
	}
	c.access.RLock()
	defer c.access.RUnlock()
	result := make(map[string]time.Time, len(c.ipList))
	for k, v := range c.ipList {
		result[k] = v
	}
	return result
}
