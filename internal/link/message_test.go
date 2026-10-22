package link

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func sampleMessages(t *testing.T) []Message {
	src := &memSource{}
	src.add(3, event.PriorityNormal)
	evs, _ := src.Events(0, 10)
	digest := strings.Repeat("ab", 32)
	return []Message{
		&Hello{Proto: 1, Host: "ubuntu-ecom", Version: "0.3.0", Roles: []string{"capture"}, Caps: map[string]any{"af_packet_v3": true}, LastSeq: 7, Token: "tok"},
		&Welcome{Proto: 1, Enrolled: true, Config: &Config{Version: 1, Epoch: 1, Body: json.RawMessage(`{"modules":{}}`), Sig: "sig"}},
		&Heartbeat{Seq: 9, HostClock: time.Date(2026, 10, 18, 14, 3, 12, 441e6, time.UTC), SpoolDepth: 12, Modules: map[string]string{"link": "ok"}},
		&Events{Events: evs},
		&StepResult{Plan: "p", Node: "n", Epoch: 1, Seq: 2, Phase: "apply", Status: "ok", After: json.RawMessage(`{"x":1}`)},
		&Chunk{SHA256: digest, Offset: 0, Total: 3, Data: []byte("abc")},
		&ChunkHave{SHA256: digest, Ranges: [][2]uint64{{0, 100}}},
		&Ack{Seq: 42},
		&Step{Plan: "p", Node: "n", Host: "h", Epoch: 1, Seq: 1, Action: "service.state", Params: json.RawMessage(`{"unit":"ssh"}`), Sig: "s"},
		&Config{Version: 2, Body: json.RawMessage(`{}`), Sig: "s"},
		&Fetch{ID: "f1", Kind: "pcap"},
		&Control{Kind: "safe_mode", On: true},
		&RelayRequest{Target: "10.0.0.5:443", Class: "device-proxy", ID: "r1"},
		&TokenIssue{Host: "h", Token: "t", TTLS: 600},
	}
}

func TestMessageRoundTrip(t *testing.T) {
	for _, m := range sampleMessages(t) {
		typ, body, err := Marshal(m)
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		got, err := Unmarshal(typ, body)
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		a, _ := json.Marshal(m)
		b, _ := json.Marshal(got)
		if string(a) != string(b) {
			t.Errorf("%T round trip changed:\n%s\n%s", m, a, b)
		}
		if got.MsgType() != typ {
			t.Errorf("%T type mismatch", m)
		}
	}
}

func TestEventsKeepChain(t *testing.T) {
	src := &memSource{}
	src.add(5, event.PriorityHigh)
	evs, _ := src.Events(0, 10)
	typ, body, _ := Marshal(&Events{Events: evs})
	m, err := Unmarshal(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	prevSeq, prevHash := uint64(0), event.GenesisHash
	for _, e := range m.(*Events).Events {
		if err := e.Verify(prevSeq, prevHash); err != nil {
			t.Fatalf("hash chain did not survive the wire: %v", err)
		}
		prevSeq, prevHash = e.Seq, e.Hash
	}
}

func TestInvalidMessagesRejected(t *testing.T) {
	bad := []struct {
		t    Type
		body string
	}{
		{TypeHello, `{"proto":1}`},                    // no host
		{TypeHello, `{"proto":0,"host":"h"}`},         // bad proto
		{TypeHello, `{"proto":1,"host":"h"} {"x":1}`}, // trailing data
		{TypeHello, `not json`},                       //
		{TypeEvents, `{"events":[]}`},                 // empty batch
		{TypeEvents, `{"events":[{"agent":"a","seq":0,"kind":"k"}]}`},
		{TypeChunk, `{"sha256":"zz","offset":0,"total":1,"data":"YQ=="}`},
		{TypeChunk, `{"sha256":"` + hex.EncodeToString(make([]byte, 32)) + `","offset":5,"total":6,"data":"YWJj"}`}, // past end
		{TypeRelayRequest, `{"target":"nohostport","class":"x","id":"1"}`},
		{TypeTokenIssue, `{"host":"h","token":"t","ttl_s":0}`},
		{Type(0x3f), `{}`},
	}
	for _, b := range bad {
		if _, err := Unmarshal(b.t, []byte(b.body)); err == nil {
			t.Errorf("accepted %s %s", b.t, b.body)
		}
	}
	if _, err := Unmarshal(Type(0x3f), []byte(`{}`)); !errors.Is(err, ErrUnknownType) {
		t.Errorf("unknown type error: %v", err)
	}
	// Unknown JSON fields are tolerated (additive evolution within a version).
	if _, err := Unmarshal(TypeAck, []byte(`{"seq":1,"future":true}`)); err != nil {
		t.Errorf("unknown field rejected: %v", err)
	}
}

func TestEveryTypeHasConstructorAndName(t *testing.T) {
	for typ, name := range typeNames {
		m := newMessage(typ)
		if m == nil || m.MsgType() != typ || typ.String() != name {
			t.Errorf("type %s inconsistent", name)
		}
		if typ&compressedFlag != 0 {
			t.Errorf("type %s collides with compression flag", name)
		}
	}
}
