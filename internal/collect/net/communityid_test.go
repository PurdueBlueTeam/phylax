package netmod

import (
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// Vectors from the Community ID spec / reference implementations.
func TestCommunityIDVectors(t *testing.T) {
	cases := []struct {
		name     string
		proto    uint8
		src, dst string
		want     string
	}{
		{"tcp", ProtoTCP, "128.232.110.120:34855", "66.35.250.204:80", "1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
		{"udp", ProtoUDP, "192.168.1.52:54585", "8.8.8.8:53", "1:d/FP5EW3wiY1vCndhwleRRKHowQ="},
	}
	for _, c := range cases {
		got := CommunityID(0, c.proto, ap(c.src), ap(c.dst))
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
		if rev := CommunityID(0, c.proto, ap(c.dst), ap(c.src)); rev != got {
			t.Errorf("%s: not direction independent: %s vs %s", c.name, rev, got)
		}
	}
}

func TestCommunityIDICMPAndSeed(t *testing.T) {
	a, b := netip.MustParseAddr("192.168.0.89"), netip.MustParseAddr("192.168.0.1")
	if got, want := CommunityIDICMP(0, ProtoICMP, a, b, 8, 0), "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="; got != want {
		t.Errorf("icmp echo: got %s want %s", got, want)
	}
	// request and reply are the same flow
	if CommunityIDICMP(0, ProtoICMP, a, b, 8, 0) != CommunityIDICMP(0, ProtoICMP, b, a, 0, 0) {
		t.Error("echo request/reply differ")
	}
	if CommunityID(0, ProtoTCP, ap("1.2.3.4:1"), ap("5.6.7.8:2")) == CommunityID(1, ProtoTCP, ap("1.2.3.4:1"), ap("5.6.7.8:2")) {
		t.Error("seed ignored")
	}
	// v4-mapped addresses equal plain v4
	if CommunityID(0, ProtoTCP, ap("[::ffff:1.2.3.4]:1"), ap("5.6.7.8:2")) != CommunityID(0, ProtoTCP, ap("1.2.3.4:1"), ap("5.6.7.8:2")) {
		t.Error("mapped address not unmapped")
	}
}
