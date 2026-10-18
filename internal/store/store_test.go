package store

import (
	"testing"
	"time"
)

func TestEnrollAndHosts(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.GetHost("ecom"); err == nil {
		t.Fatal("expected no such host")
	}
	if err := s.EnrollHost("ecom", "pin1", "key1", []string{"capture"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnrollHost("relay", "pin2", "key2", []string{"relay"}); err != nil {
		t.Fatal(err)
	}
	hs, err := s.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 2 || hs[0].Name != "ecom" || hs[1].Name != "relay" {
		t.Fatalf("hosts = %+v", hs)
	}
	h, err := s.GetHost("ecom")
	if err != nil {
		t.Fatal(err)
	}
	if h.Pin != "pin1" || len(h.Roles) != 1 || h.Roles[0] != "capture" || h.Status != "enrolled" {
		t.Fatalf("host = %+v", h)
	}
}

func TestEventsAndAcks(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.EnrollHost("ecom", "pin", "key", nil)

	new1, err := s.RecordEvent("ecom", Event{Seq: 1, TS: "t1", Type: "process_start", Data: []byte("a"), Hash: "h1"})
	if err != nil || !new1 {
		t.Fatalf("first record: %v %v", new1, err)
	}
	dup, err := s.RecordEvent("ecom", Event{Seq: 1, TS: "t1", Type: "process_start", Data: []byte("a"), Hash: "h1"})
	if err != nil || dup {
		t.Fatalf("duplicate should be ignored: %v %v", dup, err)
	}
	s.RecordEvent("ecom", Event{Seq: 2, TS: "t2", Type: "conn", Data: []byte("b"), Hash: "h2"})

	if n, _ := s.EventCount("ecom"); n != 2 {
		t.Fatalf("count = %d", n)
	}
	if mx, _ := s.MaxEventSeq("ecom"); mx != 2 {
		t.Fatalf("max seq = %d", mx)
	}
	if h, ok := s.ChainAt("ecom", 1); !ok || h != "h1" {
		t.Fatalf("chain at 1 = %q %v", h, ok)
	}
	if h, ok := s.ChainAt("ecom", 99); ok {
		t.Fatalf("chain at 99 = %q", h)
	}

	if a, _ := s.Acked("ecom"); a != 0 {
		t.Fatalf("acked = %d", a)
	}
	s.SetAcked("ecom", 2)
	s.SetAcked("ecom", 1) // monotonic: must not regress
	if a, _ := s.Acked("ecom"); a != 2 {
		t.Fatalf("acked after monotonic = %d", a)
	}
}

func TestHeartbeatAndDark(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.EnrollHost("ecom", "pin", "key", nil)
	s.EnrollHost("relay", "pin", "key", nil)

	now := time.Now().UTC()
	if err := s.TouchHeartbeat("ecom", now, 5, "hash5"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchHeartbeat("relay", now.Add(-30*time.Second), 0, ""); err != nil {
		t.Fatal(err)
	}

	// 15 s silence threshold: relay is dark, ecom is not.
	dark, err := s.HostsDarkAfter(now.Add(-15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(dark) != 1 || dark[0] != "relay" {
		t.Fatalf("dark = %v", dark)
	}

	if err := s.MarkDark("relay", true); err != nil {
		t.Fatal(err)
	}
	h, _ := s.GetHost("relay")
	if h.Status != "dark" {
		t.Fatalf("relay status = %s", h.Status)
	}
}

func TestTokens(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tok, err := s.IssueToken("ecom", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	host, err := s.ConsumeToken(tok)
	if err != nil || host != "ecom" {
		t.Fatalf("consume = %q %v", host, err)
	}
	if _, err := s.ConsumeToken(tok); err == nil {
		t.Fatal("second use of token must fail")
	}
	if _, err := s.ConsumeToken("phylax_bogus"); err == nil {
		t.Fatal("unknown token must fail")
	}

	// Expired token.
	short, _ := s.IssueToken("relay", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := s.ConsumeToken(short); err == nil {
		t.Fatal("expired token must fail")
	}
}
