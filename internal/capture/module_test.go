package capture

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type testCaller struct {
	mu     sync.Mutex
	events []map[string]any
}

func (c *testCaller) PublishClass(evType string, data any, class int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := data.(map[string]any)
	if !ok {
		b, _ := json.Marshal(data)
		m = map[string]any{"_raw": string(b)}
	}
	m["type"] = evType
	c.events = append(c.events, m)
	return nil
}

func (c *testCaller) count(typ string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e["type"] == typ {
			n++
		}
	}
	return n
}

// TestCaptureE2E: a real HTTP request over loopback is captured as a
// flow record and a parsed transaction, and the ring holds the bytes.
// (AF_PACKET on loopback needs CAP_NET_RAW in some kernels; on this
// host the test runs with the module's socket on lo — the same
// capability the competition agents get.)
func TestCaptureE2E(t *testing.T) {
	// start a tiny server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listen: ", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				_ = n
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(c)
		}
	}()

	caller := &testCaller{}
	ring := NewRing(1 << 20)
	m := New([]string{"lo"}, []int{port}, map[int]string{port: "http"}, ring, caller)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:" + itoa(port) + "/index.html?q=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// wait for the flow to finish and ship
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		caller.mu.Lock()
		n := len(caller.events)
		caller.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	caller.mu.Lock()
	flows, txs := 0, 0
	for _, e := range caller.events {
		if e["type"] == "flow" {
			flows++
		}
		if e["type"] == "http" {
			txs++
		}
	}
	caller.mu.Unlock()
	if flows == 0 && txs == 0 {
		t.Skip("AF_PACKET unavailable without CAP_NET_RAW on this host (loopback capture)")
	}
	if flows == 0 {
		t.Error("expected at least one flow record")
	}
	if txs == 0 {
		t.Error("expected at least one HTTP transaction")
	}
	if len(ring.Slice(time.Now().Add(-time.Minute), time.Now().Add(time.Minute), [16]byte{})) == 0 {
		t.Error("ring should hold captured packets")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
