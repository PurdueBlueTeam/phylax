package module

import (
	"encoding/json"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationRoundTrip(t *testing.T) {
	var s struct {
		Dead Duration `json:"dead" yaml:"dead"`
	}
	if err := yaml.Unmarshal([]byte("dead: 90s\n"), &s); err != nil || s.Dead.Duration != 90*time.Second {
		t.Fatalf("%v %v", s, err)
	}
	if err := json.Unmarshal([]byte(`{"dead":"2m"}`), &s); err != nil || s.Dead.Duration != 2*time.Minute {
		t.Fatalf("%v %v", s, err)
	}
	b, _ := json.Marshal(s)
	if string(b) != `{"dead":"2m0s"}` {
		t.Fatalf("%s", b)
	}
	for _, bad := range []string{`{"dead":90}`, `{"dead":"-5s"}`, `{"dead":""}`, `{"dead":"soon"}`} {
		if json.Unmarshal([]byte(bad), &s) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
