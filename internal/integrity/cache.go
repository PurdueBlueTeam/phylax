package integrity

import (
	"container/list"
	"sync"
)

// fileID is the cache key: dev+inode+ctime+size (Path only on platforms with
// no inode).
type fileID struct {
	Dev, Ino uint64
	CtimeNs  int64
	Size     int64
	Path     string
}

type hashCache struct {
	mu  sync.Mutex
	max int
	m   map[fileID]*list.Element
	l   *list.List
}

type cacheItem struct {
	id  fileID
	sum Sum
}

func newHashCache(max int) *hashCache {
	if max <= 0 {
		max = 65536
	}
	return &hashCache{max: max, m: map[fileID]*list.Element{}, l: list.New()}
}

func (c *hashCache) get(id fileID) (Sum, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[id]; ok {
		c.l.MoveToFront(e)
		return e.Value.(*cacheItem).sum, true
	}
	return Sum{}, false
}

func (c *hashCache) put(id fileID, s Sum) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[id]; ok {
		e.Value.(*cacheItem).sum = s
		c.l.MoveToFront(e)
		return
	}
	c.m[id] = c.l.PushFront(&cacheItem{id, s})
	for c.l.Len() > c.max {
		b := c.l.Back()
		delete(c.m, b.Value.(*cacheItem).id)
		c.l.Remove(b)
	}
}

func (c *hashCache) len() int { c.mu.Lock(); defer c.mu.Unlock(); return c.l.Len() }
