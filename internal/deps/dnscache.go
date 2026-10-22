package deps

import (
	"net/netip"
	"sync"
	"time"
)

// DNSCache remembers which name an address was resolved from, so an edge can
// say "ldap.corp.local" rather than only an address. The DNS producer calls
// Note; the collector calls Lookup when an edge is first seen. Bounded and
// safe for concurrent use.
type DNSCache struct {
	mu  sync.Mutex
	max int
	ttl time.Duration
	m   map[netip.Addr]dnsRec
}

type dnsRec struct {
	name string
	at   time.Time
}

// NewDNSCache returns a cache holding at most max (default 4096) answers, each
// usable for ttl (default 10m) after it was seen.
func NewDNSCache(max int, ttl time.Duration) *DNSCache {
	if max <= 0 {
		max = 4096
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &DNSCache{max: max, ttl: ttl, m: map[netip.Addr]dnsRec{}}
}

// Note records that name resolved to addrs at time at.
func (d *DNSCache) Note(name string, addrs []netip.Addr, at time.Time) {
	if d == nil || name == "" {
		return
	}
	if len(name) > 255 {
		name = name[:255]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range addrs {
		if _, ok := d.m[a]; !ok && len(d.m) >= d.max {
			// Evict the oldest answer.
			var oa netip.Addr
			var ot time.Time
			first := true
			for k, v := range d.m {
				if first || v.at.Before(ot) {
					oa, ot, first = k, v.at, false
				}
			}
			delete(d.m, oa)
		}
		d.m[a] = dnsRec{name, at}
	}
}

// Lookup returns the name addr was last resolved from within the ttl before now.
func (d *DNSCache) Lookup(a netip.Addr, now time.Time) string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.m[a]
	if !ok || now.Sub(r.at) > d.ttl {
		return ""
	}
	return r.name
}
