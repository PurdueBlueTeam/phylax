package module

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

func TestSchemaOfStruct(t *testing.T) {
	type inner struct {
		N int `json:"n"`
	}
	type cfg struct {
		Common
		Level  int               `json:"level"`
		Hosts  []string          `json:"hosts,omitempty"`
		Inner  inner             `json:"inner"`
		Map    map[string]string `json:"map,omitempty"`
		Window Duration          `json:"window,omitempty"`
	}
	b, err := Schema(cfg{})
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	_ = json.Unmarshal(b, &s)
	props := s["properties"].(map[string]any)
	for _, k := range []string{"enabled", "act_enabled", "autonomy", "level", "hosts", "inner", "map", "window"} {
		if _, ok := props[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if s["additionalProperties"] != false || props["level"].(map[string]any)["type"] != "integer" {
		t.Fatalf("%s", b)
	}
}

func TestSchemaRejectsBareTimeDuration(t *testing.T) {
	type bad struct {
		Common
		D time.Duration `json:"d"`
	}
	if _, err := Schema(bad{}); err == nil {
		t.Fatal("a bare time.Duration in a settings struct must be an error")
	}
}

func TestSchemaOfDuration(t *testing.T) {
	type cfg struct {
		Common
		Window Duration `json:"window"`
	}
	b, err := Schema(cfg{})
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	w, ok := s["properties"].(map[string]any)["window"].(map[string]any)
	if !ok || w["type"] != "string" {
		t.Fatalf("window schema %v (%s)", w, b)
	}
	pat, _ := w["pattern"].(string)
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("pattern %q: %v", pat, err)
	}
	for _, good := range []string{"90s", "2m", "1h30m"} {
		if !re.MatchString(good) {
			t.Errorf("%q does not match %q", good, pat)
		}
	}
	for _, bad := range []string{"90", ""} {
		if re.MatchString(bad) {
			t.Errorf("%q matches %q", bad, pat)
		}
	}
}
