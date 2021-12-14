package certs

import (
	"container/list"
	"sync"
)


// Simple LRU cache.
type Cache struct {
	// Maximum number of entries to store, or 0 for unlimited.
	Capacity int

	x sync.Mutex
	l *list.List
	m map[string]*list.Element
}

// Creates a new LRU cache with the given capacity.
func NewCache(capacity int) *Cache {
	return &Cache{
		Capacity: capacity,
		l: list.New(),
		m: make(map[string]*list.Element),
	}
}

// Adds an entry to the cache, or updates an existing entry.
func (c *Cache) Add(key string, value interface{}) {
	c.x.Lock()
	defer c.x.Unlock()

	if c.m == nil {
		c.l = list.New()
		c.m = make(map[string]*list.Element)
	}

	if e, ok := c.m[key]; ok {
		c.l.MoveToFront(e)
		e.Value.(*entry).value = value
		return
	}

	e := c.l.PushFront(&entry{key, value})
	c.m[key] = e

	if c.Capacity > 0 && c.l.Len() > c.Capacity {
		c.pop()
	}
}

// Gets an entry from the cache if it exists.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.x.Lock()
	defer c.x.Unlock()

	if c.m == nil {
		return nil, false
	}

	if e, ok := c.m[key]; ok {
		c.l.MoveToFront(e)
		return e.Value.(*entry).value, true
	}

	return nil, false
}

func (c *Cache) pop() {
	if c.m == nil {
		return
	}

	if e := c.l.Back(); e != nil {
		c.l.Remove(e)
		delete(c.m, e.Value.(*entry).key)
	}
}

type entry struct {
	key string
	value interface{}
}
