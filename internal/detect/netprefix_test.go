package detect

import (
	"strconv"
	"testing"
	"time"
)

func TestNetPrefixFieldsAndCompositeDistinct(t *testing.T) {
	y := ruleYAML("D", "  all:\n    - dir: inbound\n  count: {window: 5m, gte: 6, by: [raddr_net16], distinct: [laddr, lport]}\n")
	e := NewEngine(mustLoad(t, y), Options{})
	mk := func(src, dst string, port int) map[string]any {
		return map[string]any{"dir": "inbound", "raddr": src, "laddr": dst, "lport": port}
	}
	// Rotating sources inside 198.51.0.0/16 probing 6 distinct (host, port) pairs.
	var fired int
	for i := 0; i < 6; i++ {
		src := "198.51." + strconv.Itoa(i) + "." + strconv.Itoa(10+i)
		al := e.Process(ev(time.Duration(i)*time.Second, mk(src, "10.0.0."+strconv.Itoa(1+i%2), 20+i)))
		fired += len(al)
		if len(al) == 1 && al[0].Entities["raddr_net16"] != "198.51.0.0/16" {
			t.Fatalf("entity: %v", al[0].Entities)
		}
	}
	if fired != 1 {
		t.Fatalf("rotating sources in one /16 fired %d times, want 1", fired)
	}
	// The same pair repeated from many sources is one distinct target: no alert.
	e = NewEngine(mustLoad(t, y), Options{})
	for i := 0; i < 20; i++ {
		if len(e.Process(ev(time.Duration(i)*time.Second, mk("198.51.1."+strconv.Itoa(i+1), "10.0.0.1", 80)))) != 0 {
			t.Fatal("one target from many sources must not look like a scan")
		}
	}
	// Different /16s do not add up.
	e = NewEngine(mustLoad(t, y), Options{})
	for i := 0; i < 12; i++ {
		if len(e.Process(ev(time.Duration(i)*time.Second, mk("198."+strconv.Itoa(i)+".1.1", "10.0.0.1", 20+i)))) != 0 {
			t.Fatal("distinct /16 sources were merged")
		}
	}
	// IPv6 and v4-mapped sources derive a prefix too; junk yields no key component.
	rs := mustLoad(t, ruleYAML("P", "  all:\n    - dir: inbound\n")+"entities: [raddr_net24]\n")
	for _, c := range []struct{ in, want string }{{"203.0.113.77", "203.0.113.0/24"}, {"::ffff:203.0.113.77", "203.0.113.0/24"}, {"2001:db8:1:2::9", "2001:db8:1::/48"}, {"not-an-ip", ""}} {
		al := NewEngine(rs, Options{}).Process(ev(0, map[string]any{"dir": "inbound", "raddr": c.in}))
		if got := al[0].Entities["raddr_net24"]; got != c.want {
			t.Errorf("%s -> %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDistinctLoadErrors(t *testing.T) {
	for _, d := range []string{"[]", "[a, ~]"} {
		y := ruleYAML("D", "  all:\n    - x: y\n  count: {window: 1m, gte: 2, distinct: "+d+"}\n")
		if _, err := Parse("t.yml", []byte(y), LoadOptions{AllowUntested: true}); err == nil {
			t.Errorf("distinct %s accepted", d)
		}
	}
}
