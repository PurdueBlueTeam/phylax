package load

// The proxy is Task 13: NewProxy, Addr, Cut, Restore and Close.
import (
	"io"
	"net"
	"sync"
	"time"
)

// Proxy forwards TCP connections to one target and can cut every open
// connection while refusing new ones, which models a network partition
// without touching agent code.
type Proxy struct {
	ln     net.Listener
	target string
	max    int

	mu     sync.Mutex
	conns  map[net.Conn]struct{} // every open socket, both sides of a pair
	active int                   // accepted pairs, for the max
	cut    bool
	closed bool
	wg     sync.WaitGroup
}

// NewProxy listens on listen at once and forwards accepted connections to
// target. Over maxConns simultaneous accepted connections are closed (0 = no
// limit).
func NewProxy(listen, target string, maxConns int) (*Proxy, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, target: target, max: maxConns, conns: map[net.Conn]struct{}{}}
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

// Addr is the proxy's listen address.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Cut closes every open connection; until Restore an accepted connection is
// closed immediately.
func (p *Proxy) Cut() {
	p.mu.Lock()
	p.cut = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Restore allows new connections through again.
func (p *Proxy) Restore() {
	p.mu.Lock()
	p.cut = false
	p.mu.Unlock()
}

// Close stops accepting, closes every connection and waits for the
// goroutines.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	err := p.ln.Close()
	for _, c := range conns {
		c.Close()
	}
	p.wg.Wait()
	return err
}

func (p *Proxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go p.serve(c)
	}
}

// serve handles one accepted connection for the life of its pair.
func (p *Proxy) serve(c net.Conn) {
	defer p.wg.Done()
	p.mu.Lock()
	if p.closed || p.cut || (p.max > 0 && p.active >= p.max) {
		p.mu.Unlock()
		c.Close()
		return
	}
	p.active++
	p.conns[c] = struct{}{}
	p.mu.Unlock()

	u, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		p.drop(c, nil)
		return
	}
	p.mu.Lock()
	if p.closed || p.cut {
		p.mu.Unlock()
		p.drop(c, u)
		return
	}
	p.conns[u] = struct{}{}
	p.mu.Unlock()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(u, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, u); done <- struct{}{} }()
	<-done
	c.Close()
	u.Close()
	<-done
	p.drop(c, u)
}

// drop forgets one pair and closes its sockets.
func (p *Proxy) drop(c, u net.Conn) {
	c.Close()
	if u != nil {
		u.Close()
	}
	p.mu.Lock()
	delete(p.conns, c)
	if u != nil {
		delete(p.conns, u)
	}
	p.active--
	p.mu.Unlock()
}
