package honeytokens

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestScanAKIA(t *testing.T) {
	g := NewGenerator(NewRegistry())
	id := g.awsKeyID()
	cases := []struct {
		name   string
		fields map[string]any
		want   []string
	}{
		{"header", map[string]any{"headers": map[string]any{"Authorization": "AWS4-HMAC-SHA256 Credential=" + id + "/20270301/us-east-1/s3/aws4_request, SignedHeaders=host"}}, []string{id}},
		{"dns label is lower-cased", map[string]any{"qname": lower(id) + ".exfil.example.net"}, []string{id}},
		{"query string", map[string]any{"path": "/x?AWSAccessKeyId=" + id + "&Signature=abc"}, []string{id}},
		{"list of strings", map[string]any{"lines": []any{"nothing", "key=" + id}}, []string{id}},
		{"longer base32 run is not a key id", map[string]any{"s": id + "ABCD"}, nil},
		{"embedded in a word", map[string]any{"s": "xAKIA" + id[4:]}, nil},
		{"digit 1 is not base32", map[string]any{"s": "AKIA1111111111111111"}, nil},
		{"too short", map[string]any{"s": "AKIAABCDEFG"}, nil},
		{"already tagged is skipped by the scanner", map[string]any{FieldAWSKeyID: id}, nil},
	}
	for _, c := range cases {
		got := ScanAKIA(c.fields)
		if len(got) != len(c.want) || (len(got) == 1 && got[0] != c.want[0]) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// bounded
	big := map[string]any{}
	for i := range 40 {
		big[string(rune('a'+i%26))+string(rune('a'+i/26))] = "AKIA" + g.awsKeyID()[4:]
	}
	if n := len(ScanAKIA(big)); n > maxScanKeys {
		t.Errorf("unbounded: %d keys", n)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestAKIAEventsKindsAndNoLoop(t *testing.T) {
	g := NewGenerator(NewRegistry())
	id := g.awsKeyID()
	for _, kind := range []string{"http_request", "net.sinkhole_capture", "dns_query"} {
		in := event.Event{Kind: kind, Time: time.Now(), Fields: map[string]any{"source": "10.0.0.23", "body": "k=" + id}}
		out := AKIAEvents(in)
		if len(out) != 1 || out[0].Kind != kind || out[0].Fields[FieldAWSKeyID] != id || out[0].Fields["source"] != "10.0.0.23" {
			t.Fatalf("%s: %+v", kind, out)
		}
		if out[0].Priority != event.PriorityCritical {
			t.Errorf("priority %v", out[0].Priority)
		}
		if again := AKIAEvents(out[0]); len(again) != 0 {
			t.Errorf("%s: derived event rescanned: %v", kind, again)
		}
	}
	if AKIAEvents(event.Event{Kind: "proc_exec", Fields: map[string]any{"cmd": id}}) != nil {
		t.Error("unscanned kind produced an event")
	}
}

func TestAKIAScannerModule(t *testing.T) {
	g := NewGenerator(NewRegistry())
	id := g.awsKeyID()
	ch := make(chan event.Event, 4)
	m := &AKIAScanner{Subscribe: func(int) (<-chan event.Event, func()) { return ch, func() {} }}
	got := make(chan event.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Start(ctx, func(e event.Event) error { got <- e; return nil })
	ch <- event.Event{Kind: "http_request", Fields: map[string]any{"source": "10.0.0.9", "uri": "/?k=" + id}}
	select {
	case e := <-got:
		if e.Fields[FieldAWSKeyID] != id {
			t.Fatalf("%v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no derived event")
	}
}
