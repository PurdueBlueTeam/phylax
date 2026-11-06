package event

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCanonicalOmitsZeroSchemaAndTag(t *testing.T) {
	c, _ := Event{Agent: "a", Kind: "k"}.Canonical()
	if bytes.Contains(c, []byte(`"schema"`)) || bytes.Contains(c, []byte(`"tag"`)) {
		t.Fatalf("zero schema/tag must be omitted: %s", c)
	}
}

func TestCanonicalCarriesSchemaAndTag(t *testing.T) {
	c, _ := Event{Agent: "a", Kind: "k", Schema: 1, Tag: "plan:p1"}.Canonical()
	for _, want := range []string{`"schema":1`, `"tag":"plan:p1"`} {
		if !bytes.Contains(c, []byte(want)) {
			t.Fatalf("missing %s in %s", want, c)
		}
	}
}

func TestTagCoveredByHash(t *testing.T) {
	e := Event{Agent: "a", Kind: "k", Schema: 1, Tag: "w:1", Time: time.Unix(1, 0)}
	if err := e.Seal(0, GenesisHash); err != nil {
		t.Fatal(err)
	}
	e.Tag = "w:2"
	if err := e.Verify(0, GenesisHash); !errors.Is(err, ErrChain) {
		t.Fatalf("tag change not detected: %v", err)
	}
}

func TestPreSchemaEventStillVerifies(t *testing.T) {
	const oldHash = "85a0be0fc3e270876e62b0f095885e7f92e52c0e8ec85b92c1b4f20277958ddc"
	e := Event{Agent: "a", Seq: 1, Time: time.Unix(0, 0).UTC(), Kind: "k", Priority: PriorityNormal, Fields: map[string]any{"x": "y"}, Hash: oldHash}
	if err := e.Verify(0, GenesisHash); err != nil {
		t.Fatalf("old event no longer verifies: %v", err)
	}
}
