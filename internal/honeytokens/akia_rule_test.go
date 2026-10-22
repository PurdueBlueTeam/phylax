package honeytokens

import (
	"os"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// The scanner's output must be what rule D15g (rules/deception.yml) matches,
// with the profile seeded from Registry.Seeds, end to end through the engine.
func TestDerivedEventMatchesRuleD15g(t *testing.T) {
	raw, err := os.ReadFile("../../rules/deception.yml")
	if err != nil {
		t.Skip("rules/deception.yml not present: " + err.Error())
	}
	rs, err := detect.Parse("deception", raw, detect.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry()
	g := NewGenerator(reg)
	hp, err := g.ForHost(HostSpec{Host: "rocky-ecom", Tokens: []TokenDef{{Kind: "aws_key"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyID := hp.Tokens[0].User
	eng := detect.NewEngine(rs, detect.Options{AlertOnly: true})
	for p, vals := range reg.Seeds() {
		if len(vals) > 0 {
			if err := eng.Seed(p, nil, vals...); err != nil {
				t.Fatal(err)
			}
		}
	}
	probe := func(body string) []detect.Alert {
		var alerts []detect.Alert
		in := event.Event{Kind: "http_request", Time: time.Now(), Fields: map[string]any{"source": "10.0.0.23", "uri": body}}
		for _, d := range AKIAEvents(in) {
			alerts = append(alerts, eng.Process(d)...)
		}
		return alerts
	}
	al := probe("/upload?AWSAccessKeyId=" + keyID)
	if len(al) != 1 || al[0].RuleID != "D15g.canary-aws-key" {
		t.Fatalf("alerts: %+v", al)
	}
	if other := probe("/?AWSAccessKeyId=" + NewGenerator(NewRegistry()).awsKeyID()); len(other) != 0 {
		t.Fatalf("a key that is not ours alerted: %+v", other)
	}
}
