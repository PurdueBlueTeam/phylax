package event

import (
	"encoding/json"
	"testing"
)

func TestWithExtraCopiesAndPrefixes(t *testing.T) {
	t.Skip("unimplemented: W1 Task 3a")
	e, _ := New("ttest.one", tPayload{A: "x"})
	f := e.WithExtra("raw_line", "su: failed")
	if f.Fields["x_raw_line"] != "su: failed" {
		t.Fatalf("%v", f.Fields)
	}
	if _, ok := e.Fields["x_raw_line"]; ok {
		t.Fatal("receiver modified")
	}
	if err := Validate(f); err != nil {
		t.Fatalf("x_ field must not fail strict validation: %v", err)
	}
	got, err := Decode[tPayload](f, "ttest.one")
	if err != nil || got.A != "x" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestWithExtraBadKeyPanics(t *testing.T) {
	t.Skip("unimplemented: W1 Task 3a")
	e, _ := New("ttest.one", tPayload{A: "x"})
	defer func() {
		if recover() == nil {
			t.Fatal("bad key accepted")
		}
	}()
	e.WithExtra("Bad Key", 1)
}

func TestWithExtraSurvivesJSONRoundTrip(t *testing.T) {
	t.Skip("unimplemented: W1 Task 3a")
	e, _ := New("ttest.one", tPayload{A: "x"})
	e = e.WithExtra("n", 3)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back.Fields["x_n"]; !ok {
		t.Fatalf("extra field lost: %v", back.Fields)
	}
	if err := Validate(back); err != nil {
		t.Fatal(err)
	}
}
