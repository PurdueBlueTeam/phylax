package event

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestCommonKindsDeclared(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4")
	want := map[string]any{KindProcessStart: ProcessStart{}, KindProcessExit: ProcessExit{}, KindFileChange: FileChange{},
		KindConn: Conn{}, KindListener: Listener{}, KindAuthEvent: AuthEvent{}, KindDNSQuery: DNSQuery{}, KindTelemetryGap: TelemetryGap{}}
	for k, f := range want {
		ty, ok := Lookup(k)
		if !ok || ty.Schema != 1 || ty.Alert || reflect.TypeOf(ty.Fields) != reflect.TypeOf(f) {
			t.Errorf("%s: %+v %v", k, ty, ok)
		}
	}
}

func TestConnCanonicalNames(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4")
	e, err := New(KindConn, Conn{Op: "opened", Dir: "inbound", Proto: "tcp", LAddr: "10.0.0.1", LPort: 80, RAddr: "10.0.0.9", RPort: 5555, Source: "net"})
	if err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(e.Fields))
	if !slices.Equal(keys, []string{"dir", "laddr", "lport", "op", "proto", "raddr", "rport", "source"}) {
		t.Fatalf("keys %v", keys)
	}
}

func TestLegacyFieldNamesRejected(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4")
	for _, f := range []map[string]any{
		{"op": "opened", "dir": "out", "proto": "tcp", "source": "net", "src_ip": "1.2.3.4"},
		{"op": "opened", "dir": "inbound", "proto": "tcp", "source": "net", "dst_port": 22},
	} {
		if Validate(Event{Kind: KindConn, Schema: 1, Fields: f}) == nil {
			t.Errorf("accepted %v", f)
		}
	}
	if Validate(Event{Kind: KindProcessStart, Schema: 1, Fields: map[string]any{"pid": 1, "exe": "/x", "source": "audit", "image": "/x"}}) == nil {
		t.Error("image accepted")
	}
}

func TestProcessStartParentObject(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4")
	e, _ := New(KindProcessStart, ProcessStart{PID: 2, Exe: "/bin/sh", Source: "audit", Parent: &ProcessParent{Exe: "/usr/sbin/httpd", Service: "ecom-http"}})
	p, ok := e.Fields["parent"].(map[string]any)
	if !ok || p["exe"] != "/usr/sbin/httpd" || p["service"] != "ecom-http" {
		t.Fatalf("parent %#v", e.Fields["parent"])
	}
}
