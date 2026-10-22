package lines

import (
	"strings"
	"testing"
)

func TestSplitAcrossWritesAndLongLines(t *testing.T) {
	var s Splitter
	var got []string
	var longs []bool
	fn := func(l []byte, long bool) bool { got = append(got, string(l)); longs = append(longs, long); return true }
	s.Write([]byte("AB"), fn)
	s.Write([]byte("C\r\nD"), fn)
	s.Write([]byte("E\nFG"), fn)
	if strings.Join(got, "|") != "ABC|DE" || s.Pending() != 2 {
		t.Fatalf("%v pending %d", got, s.Pending())
	}
	got = nil
	s.Reset()
	s.Write([]byte(strings.Repeat("x", 3*MaxLine)+"\nok\n"), fn)
	if len(got) != 2 || len(got[0]) != MaxLine || !longs[len(longs)-2] || got[1] != "ok" {
		t.Fatalf("%d lines first=%d", len(got), len(got[0]))
	}
}

func TestStopEarly(t *testing.T) {
	var s Splitter
	n := s.Write([]byte("a\nb\nc\n"), func([]byte, bool) bool { return false })
	if n != 2 {
		t.Fatalf("consumed %d", n)
	}
}

func TestDecodePlain(t *testing.T) {
	u, p, ok := DecodePlain("AGFsaWNlAHB3") // \0alice\0pw
	if !ok || u != "alice" || p != "pw" {
		t.Fatalf("%q %q %v", u, p, ok)
	}
	if _, _, ok := DecodePlain("!!"); ok {
		t.Fatal("bad base64 accepted")
	}
	if v, a := Verb("  eHlo   host "); v != "EHLO" || a != "host" {
		t.Fatalf("%q %q", v, a)
	}
	if l := Push(make([]string, MaxList), "x"); len(l) != MaxList {
		t.Fatal("list unbounded")
	}
}
