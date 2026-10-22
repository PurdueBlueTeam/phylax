package capture

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/bpf"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

type probe struct {
	name string
	cap  func(c *fixture.Capture)
	want int // snap length the program must return
}

func frame(f func(c *fixture.Capture), vlan uint16) []byte {
	c := fixture.New(time.Unix(1700000000, 0))
	c.VLAN = vlan
	f(c)
	return c.Frames[len(c.Frames)-1].Data
}

func TestFilterVMClassifiesFrames(t *testing.T) {
	f := Filter{Ports: []uint16{22, 80, 443, 445}, SnapScored: 9000, SnapOther: 128,
		Exclude: []netip.AddrPort{ap("172.20.240.50:9443"), ap("[fd00::50]:9443")}}
	prog, err := f.Instructions()
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	cases := []probe{
		{"v4 tcp dst scored", func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("10.0.0.9:80")).SYNOnly() }, 9000},
		{"v4 tcp src scored (reply)", func(c *fixture.Capture) { c.TCP(ap("10.0.0.9:443"), ap("10.0.0.5:50000")).SYNOnly() }, 9000},
		{"v4 tcp other", func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("10.0.0.9:8123")).SYNOnly() }, 128},
		{"v4 udp scored", func(c *fixture.Capture) { c.UDP(ap("10.0.0.5:5000"), ap("10.0.0.9:22"), []byte("x")) }, 9000},
		{"v4 udp other", func(c *fixture.Capture) { c.UDP(ap("10.0.0.5:5000"), ap("10.0.0.9:5001"), []byte("x")) }, 128},
		{"v4 icmp echo", func(c *fixture.Capture) {
			c.Echo(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), false, 1, 1, nil)
		}, 9000},
		{"v6 tcp scored", func(c *fixture.Capture) { c.TCP(ap("[fd00::5]:50000"), ap("[fd00::9]:445")).SYNOnly() }, 9000},
		{"v6 tcp other", func(c *fixture.Capture) { c.TCP(ap("[fd00::5]:50000"), ap("[fd00::9]:1")).SYNOnly() }, 128},
		{"v6 icmp", func(c *fixture.Capture) {
			c.Echo(netip.MustParseAddr("fd00::5"), netip.MustParseAddr("fd00::9"), false, 1, 1, nil)
		}, 9000},
		{"controller v4 dst dropped", func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("172.20.240.50:9443")).SYNOnly() }, 0},
		{"controller v4 src dropped", func(c *fixture.Capture) { c.TCP(ap("172.20.240.50:9443"), ap("10.0.0.5:50000")).SYNOnly() }, 0},
		{"controller v6 dropped", func(c *fixture.Capture) { c.TCP(ap("[fd00::5]:50000"), ap("[fd00::50]:9443")).SYNOnly() }, 0},
		{"same ip, other port kept", func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("172.20.240.50:80")).SYNOnly() }, 9000},
	}
	for _, vlan := range []uint16{0, 100} {
		for _, p := range cases {
			got, err := vm.Run(frame(p.cap, vlan))
			if err != nil {
				t.Fatalf("%s: %v", p.name, err)
			}
			if got != p.want {
				t.Errorf("vlan=%d %s: snap %d want %d", vlan, p.name, got, p.want)
			}
		}
	}
	// non-IP (ARP-like) and truncated frames are other, never a crash
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	if got, _ := vm.Run(arp); got != 128 {
		t.Errorf("arp: %d", got)
	}
}

func TestOnlyScoredDropsEverythingElse(t *testing.T) {
	prog, err := Filter{Ports: []uint16{80}, OnlyScored: true}.Instructions()
	if err != nil {
		t.Fatal(err)
	}
	vm, _ := bpf.NewVM(prog)
	other := frame(func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("10.0.0.9:8123")).SYNOnly() }, 0)
	if got, _ := vm.Run(other); got != 0 {
		t.Fatalf("unscored kept: %d", got)
	}
	scored := frame(func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("10.0.0.9:80")).SYNOnly() }, 0)
	if got, _ := vm.Run(scored); got != SnapFull {
		t.Fatalf("scored: %d", got)
	}
}

func TestFilterLimitsAndKernelForm(t *testing.T) {
	var ports []uint16
	for i := 0; i < maxFilterPorts+1; i++ {
		ports = append(ports, uint16(1000+i))
	}
	if _, err := (Filter{Ports: ports}).Instructions(); err == nil {
		t.Fatal("too many ports accepted")
	}
	// the largest allowed filter, with controller exclusions, must still assemble
	// (jump offsets are one byte) and run
	ports = ports[:maxFilterPorts]
	f := Filter{Ports: ports, Exclude: []netip.AddrPort{ap("10.1.1.1:1"), ap("10.1.1.2:2"), ap("[fd00::1]:3"), ap("[fd00::2]:4")}}
	raw, err := f.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100 || len(raw) > 4096 {
		t.Fatalf("program length %d", len(raw))
	}
	prog, _ := f.Instructions()
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	last := frame(func(c *fixture.Capture) { c.TCP(ap("10.0.0.5:50000"), ap("10.0.0.9:1047")).SYNOnly() }, 100)
	if got, _ := vm.Run(last); got != SnapFull {
		t.Fatalf("last port in the list not matched: %d", got)
	}
}
