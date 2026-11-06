package event

import "testing"

func TestExtensionFieldsRoundTrip(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4a")
	argc := 0
	in := ProcessStart{PID: 7, Exe: "/usr/bin/su", Source: "audit", Argc: &argc, CGroup: "/system.slice/x", StartTicks: 99,
		Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"}, Parent: &ProcessParent{Exe: "/bin/bash", PID: 3, Live: true}}
	e, err := New(KindProcessStart, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode[ProcessStart](e, KindProcessStart)
	if err != nil || out.Argc == nil || *out.Argc != 0 || out.Env["LD_PRELOAD"] != "/tmp/x.so" || out.Parent.PID != 3 {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestZeroArgcSurvives(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4a")
	zero := 0
	e, _ := New(KindProcessStart, ProcessStart{PID: 1, Exe: "/x", Source: "audit", Argc: &zero})
	if _, ok := e.Fields["argc"]; !ok {
		t.Fatal("argc 0 dropped by omitempty")
	}
}

func TestUnknownFieldStillRejected(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4a")
	e, _ := New(KindConn, Conn{Op: "opened", Dir: "outbound", Proto: "tcp", Source: "net"})
	e.Fields["srcip"] = "10.0.0.1" // a retired name
	if Validate(e) == nil {
		t.Fatal("unknown field accepted")
	}
	e2, _ := New(KindConn, Conn{Op: "opened", Dir: "outbound", Proto: "tcp", Source: "net", ExeSHA256: "ab", PIDStart: 5, Replay: true})
	if err := Validate(e2); err != nil {
		t.Fatal(err)
	}
}

func TestReplayOnFourKinds(t *testing.T) {
	t.Skip("unimplemented: W1 Task 4a")
	for _, c := range []struct {
		kind string
		v    any
	}{
		{KindProcessStart, ProcessStart{PID: 1, Exe: "/x", Source: "audit", Replay: true}},
		{KindFileChange, FileChange{Op: "modify", Path: "/x", Source: "audit", Replay: true}},
		{KindConn, Conn{Op: "opened", Dir: "outbound", Proto: "tcp", Source: "net", Replay: true}},
		{KindAuthEvent, AuthEvent{Result: "fail", Account: "a", Service: "ssh", Replay: true}},
	} {
		e, err := New(c.kind, c.v)
		if err != nil {
			t.Fatal(err)
		}
		if e.Fields["replay"] != true {
			t.Errorf("%s: replay missing: %v", c.kind, e.Fields)
		}
	}
}
