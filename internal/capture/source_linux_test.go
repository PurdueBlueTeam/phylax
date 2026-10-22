//go:build linux

package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// requireDocker gates tests that open a real AF_PACKET socket: they run only
// inside a container (the capture sees that container's own network namespace,
// never the developer machine's interfaces) and only when asked for.
func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("PHYLAX_CAPTURE_DOCKER") != "1" {
		t.Skip("real AF_PACKET capture test: set PHYLAX_CAPTURE_DOCKER=1 and run inside a container with NET_RAW (see docs/capture.md)")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("PHYLAX_CAPTURE_DOCKER=1 but /.dockerenv is absent: refusing to open AF_PACKET on a host's real interfaces")
	}
}

func TestAFPacketTPACKETV3OnContainerLoopback(t *testing.T) {
	requireDocker(t)

	// Test-owned HTTP server on loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from the test server")
	})}
	go srv.Serve(ln)
	defer srv.Close()

	// A second, unscored port that must be filtered out by the kernel program.
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port

	src, err := OpenInterface(InterfaceOptions{
		Name:   "lo",
		Filter: Filter{Ports: []uint16{port}, OnlyScored: true},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer src.Close()

	var mu sync.Mutex
	var txns []txn.Txn
	var flows []Flow
	eng := NewEngine(Config{
		ScoredPorts: []uint16{port},
		Services:    map[uint16]string{port: "http"},
		OnTxn:       func(x txn.Txn) { mu.Lock(); txns = append(txns, x); mu.Unlock() },
		OnFlow:      func(f Flow) { mu.Lock(); flows = append(flows, f); mu.Unlock() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, src, eng) }()

	// Traffic: one HTTP request on the scored port, and datagrams on the unscored one.
	c, _ := net.Dial("udp", udp.LocalAddr().String())
	for i := 0; i < 5; i++ {
		_, _ = c.Write([]byte("noise"))
	}
	c.Close()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/index.php", port), nil)
	req.Header.Set("Connection", "close")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from the test server" {
		t.Fatalf("body %q", body)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(txns)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(txns) != 1 || txns[0].Proto != "http" || txns[0].Attr["http.path"] != "/index.php" || txns[0].Attr["http.status"] != "200" ||
		txns[0].Attr["http.resp_body_len"] != "26" {
		t.Fatalf("http transaction from the live ring: %+v", txns)
	}
	if len(flows) == 0 || flows[0].Handshake != "established" || flows[0].CommunityID == "" {
		t.Fatalf("flows: %+v", flows)
	}
	st := src.Stats()
	if st.Packets == 0 {
		t.Fatalf("no packets: %+v", st)
	}
	// the kernel filter kept the unscored UDP traffic out of the ring entirely
	var out bytes.Buffer
	n, err := eng.Ring().WriteSlice(&out, time.Unix(0, 0), time.Now().Add(time.Hour), nil)
	if err != nil || n == 0 {
		t.Fatalf("ring: n=%d err=%v", n, err)
	}
	_, _, _, datas := readPCAP(t, out.Bytes())
	for _, d := range datas {
		if bytes.Contains(d, []byte("noise")) {
			t.Fatalf("unscored datagram on port %d reached the ring: the kernel filter did not apply", udpPort)
		}
	}
	t.Logf("TPACKET_V3 on lo: %d packets captured, %d dropped by kernel, ring %d packets, port %d", st.Packets, st.Drops, n, port)
}

func TestOpenInterfaceRejectsBadGeometryWithoutSocket(t *testing.T) {
	// validation happens before any socket is opened, so this is safe anywhere
	if _, err := OpenInterface(InterfaceOptions{Name: "lo", BlockSize: 1000}); err == nil {
		t.Fatal("non page-multiple block size accepted")
	}
	if _, err := OpenInterface(InterfaceOptions{Name: "lo", Filter: Filter{Ports: make([]uint16, 100)}}); err == nil {
		t.Fatal("oversized filter accepted")
	}
}
