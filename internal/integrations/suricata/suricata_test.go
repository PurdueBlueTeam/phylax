package suricata

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommunityIDVector(t *testing.T) {
	// Official Community ID test vector (TCP 128.232.110.120:34855 -> 66.35.250.204:80).
	got := CommunityID("128.232.110.120", "66.35.250.204", 34855, 80, "tcp")
	if got != "1:LQU9qZlK+B5F3KDmev6m5PMibrg=" {
		t.Fatal(got)
	}
	// Direction independent.
	if CommunityID("66.35.250.204", "128.232.110.120", 80, 34855, "tcp") != got {
		t.Fatal("not symmetric")
	}
	if CommunityID("x", "1.1.1.1", 1, 2, "tcp") != "" || CommunityID("1.1.1.1", "2.2.2.2", 1, 2, "gre") != "" {
		t.Fatal("bad input accepted")
	}
}

func TestReadEVE(t *testing.T) {
	f, _ := os.Open("testdata/eve.json")
	defer f.Close()
	evs, st, err := ReadEVE(f, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || st.Bad != 1 || st.Skipped != 2 {
		t.Fatalf("%d events, %+v", len(evs), st)
	}
	if !evs[0].Time.Before(evs[1].Time) || evs[0].Fields["signature_id"] != 2001219 || evs[0].Kind != KindAlert {
		t.Fatalf("not time-sorted or wrong parse: %+v", evs[0])
	}
	if evs[0].Priority >= evs[1].Priority { // severity 1 outranks 2
		t.Fatalf("priorities %v %v", evs[0].Priority, evs[1].Priority)
	}
	if evs[0].Fields["community_id"] == "" { // computed when Suricata omitted it
		t.Fatal("community id not derived")
	}
	f.Seek(0, 0)
	evs, _, _ = ReadEVE(f, true)
	if len(evs) != 3 {
		t.Fatalf("context events: %d", len(evs))
	}
}

func TestZeekAndJoin(t *testing.T) {
	ef, _ := os.Open("testdata/eve.json")
	alerts, _, _ := ReadEVE(ef, false)
	cf, _ := os.Open("testdata/conn.log")
	conns, st, err := ReadZeek(cf, KindZeekConn)
	if err != nil || len(conns) != 1 || st.Bad != 1 {
		t.Fatalf("%v %+v %v", conns, st, err)
	}
	if !conns[0].Time.Equal(time.Unix(1792144802, 400000000).UTC()) && conns[0].Time.Sub(time.Unix(1792144802, 400000000)) > time.Microsecond {
		t.Fatal(conns[0].Time)
	}
	df, _ := os.Open("testdata/dns.jsonl")
	dns, _, _ := ReadZeek(df, KindZeekDNS)
	if len(dns) != 1 || dns[0].Fields["query"] != "evil.example" {
		t.Fatalf("%+v", dns)
	}
	j := Join(alerts, conns, dns)
	g := j["1:LQU9qZlK+B5F3KDmev6m5PMibrg="]
	if len(g) != 2 || g[0].Kind != KindAlert && g[1].Kind != KindAlert {
		t.Fatalf("suricata alert and zeek conn not joined by community id: %+v", g)
	}
	kinds := g[0].Kind + "," + g[1].Kind
	if !strings.Contains(kinds, "suricata.alert") || !strings.Contains(kinds, "zeek.conn") {
		t.Fatal(kinds)
	}
}

func TestOversizeLineSkipped(t *testing.T) {
	big := `{"timestamp":"2026-10-22T10:00:00.000000+0000","event_type":"alert","x":"` + strings.Repeat("a", 2<<20) + `"}` + "\n"
	ok := `{"timestamp":"2026-10-22T10:00:00.000000+0000","event_type":"alert","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","proto":"TCP","alert":{"signature_id":1,"severity":3}}` + "\n"
	evs, st, err := ReadEVE(strings.NewReader(big+ok), false)
	if err != nil || len(evs) != 1 || st.TooLong != 1 {
		t.Fatalf("%v %+v %v", len(evs), st, err)
	}
}
