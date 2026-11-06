package module

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSchemaOfStruct(t *testing.T) {
	t.Skip("unimplemented: W1 Task 33")
	type inner struct {
		N int `json:"n"`
	}
	type cfg struct {
		Common
		Level  int               `json:"level"`
		Hosts  []string          `json:"hosts,omitempty"`
		Inner  inner             `json:"inner"`
		Map    map[string]string `json:"map,omitempty"`
		Window time.Duration     `json:"window,omitempty"`
	}
	b, err := Schema(cfg{})
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	_ = json.Unmarshal(b, &s)
	props := s["properties"].(map[string]any)
	for _, k := range []string{"enabled", "act_enabled", "auto", "level", "hosts", "inner", "map", "window"} {
		if _, ok := props[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if s["additionalProperties"] != false || props["level"].(map[string]any)["type"] != "integer" {
		t.Fatalf("%s", b)
	}
}
