package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
)

type tPayload struct {
	A string `json:"a"`
	N int    `json:"n,omitempty"`
}

func init() {
	Declare(Type{Kind: "ttest.one", Schema: 2, Priority: PriorityHigh, Fields: tPayload{}})
	Declare(Type{Kind: "ttest.two", Schema: 1, Priority: PriorityNormal, Alert: true, Fields: tPayload{}})
}

func TestNewSetsTypeDefaults(t *testing.T) {
	e, err := New("ttest.one", tPayload{A: "x", N: 3})
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != "ttest.one" || e.Schema != 2 || e.Priority != PriorityHigh {
		t.Fatalf("header %+v", e)
	}
	if e.Fields["a"] != "x" || e.Fields["n"] != json.Number("3") {
		t.Fatalf("fields %#v", e.Fields)
	}
}

func TestNewUndeclared(t *testing.T) {
	if _, err := New("ttest.none", tPayload{}); !errors.Is(err, ErrUndeclared) {
		t.Fatalf("want ErrUndeclared, got %v", err)
	}
}

func TestNewWrongPayloadType(t *testing.T) {
	if _, err := New("ttest.two", struct{ B int }{1}); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("want ErrKindMismatch, got %v", err)
	}
}

func TestDecodeStrict(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x", N: 3})
	got, err := Decode[tPayload](e, "ttest.one")
	if err != nil || got != (tPayload{A: "x", N: 3}) {
		t.Fatalf("decode %+v %v", got, err)
	}
	if _, err := Decode[tPayload](e, "ttest.two"); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("kind mismatch: %v", err)
	}
	bad := e
	bad.Fields = map[string]any{"a": "x", "zz": 1}
	if _, err := Decode[tPayload](bad, "ttest.one"); err == nil {
		t.Fatal("unknown field accepted")
	}
	old := e
	old.Schema = 1
	if _, err := Decode[tPayload](old, "ttest.one"); !errors.Is(err, ErrSchema) {
		t.Fatalf("schema: %v", err)
	}
}

func TestDecodeIgnoresXPrefix(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	e.Fields["x_serial"] = "7"
	if _, err := Decode[tPayload](e, "ttest.one"); err != nil {
		t.Fatalf("x_ field rejected: %v", err)
	}
}

func TestDeclareDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	Declare(Type{Kind: "ttest.one", Schema: 1, Fields: tPayload{}})
}

func TestDeclaredSortedAndLookup(t *testing.T) {
	ts := Declared()
	if !sort.SliceIsSorted(ts, func(i, j int) bool { return ts[i].Kind < ts[j].Kind }) {
		t.Fatal("not sorted")
	}
	if ty, ok := Lookup("ttest.two"); !ok || !ty.Alert {
		t.Fatalf("lookup %+v %v", ty, ok)
	}
}

func TestValidate(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	if err := Validate(e); err != nil {
		t.Fatal(err)
	}
	e.Fields["zz"] = true
	if Validate(e) == nil {
		t.Fatal("unknown field accepted")
	}
	if err := Validate(Event{Kind: "ttest.none"}); !errors.Is(err, ErrUndeclared) {
		t.Fatalf("undeclared: %v", err)
	}
}

func TestNewMatchesStoreRoundTrip(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x", N: 3})
	raw, _ := json.Marshal(e.Fields)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var back map[string]any
	_ = dec.Decode(&back)
	if !reflect.DeepEqual(back, e.Fields) {
		t.Fatalf("bus form %#v != store form %#v", e.Fields, back)
	}
}
