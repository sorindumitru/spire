package cache

import (
	"sync"
	"time"

	"github.com/spiffe/spire/test/clock"
)

type valueWithExpiry[Value any] struct {
	expiry time.Time
	value  *Value
}

func (v *valueWithExpiry[Value]) IsExpired(clk clock.Clock) bool {
	if clk.Now().After(v.expiry) {
		return true
	}

	return false
}

type Cache[Key comparable, Value any] struct {
	clk clock.Clock

	mtx      sync.RWMutex
	previous map[Key]valueWithExpiry[Value]
	current  map[Key]valueWithExpiry[Value]

	lastGC time.Time
}

func NewCache[Key comparable, Value any](clk clock.Clock) *Cache[Key, Value] {
	return &Cache[Key, Value]{
		clk: clk,

		mtx:      sync.RWMutex{},
		previous: make(map[Key]valueWithExpiry[Value]),
		current:  make(map[Key]valueWithExpiry[Value]),

		lastGC: clk.Now(),
	}
}

func (c *Cache[Key, Value]) Get(key Key) (*Value, bool) {
	c.mtx.RLock()
	val, ok := c.current[key]
	if ok && !val.IsExpired(c.clk) {
		c.mtx.RUnlock()
		return val.value, ok
	}
	c.mtx.RUnlock()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	val, ok = c.current[key]
	if ok && !val.IsExpired(c.clk) {
		return val.value, ok
	} else if val.IsExpired(c.clk) {
		delete(c.current, key)
	} else {
		val, ok := c.previous[key]
		if ok && !val.IsExpired(c.clk) {
			c.current[key] = val
			delete(c.previous, key)
			return val.value, ok
		} else {
			delete(c.previous, key)
		}
	}

	now := c.clk.Now()
	if now.Sub(c.lastGC) >= 10*time.Second {
		c.previous = c.current
		c.current = make(map[Key]valueWithExpiry[Value])
		c.lastGC = now
	}

	return nil, false
}

func (c *Cache[Key, Value]) Set(key Key, value *Value, expiry time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Delete from the previous map, in case it's cached there
	delete(c.previous, key)

	c.current[key] = valueWithExpiry[Value]{
		value:  value,
		expiry: expiry,
	}
}

func (c *Cache[Key, Value]) Delete(key Key) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	delete(c.current, key)
	delete(c.previous, key)
}
