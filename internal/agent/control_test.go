package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func startWithKey(t *testing.T) (*fakeController, ed25519.PrivateKey, *runningAgent) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	if err := l.SaveBundle(&Bundle{Controllers: []string{ctl.addr}, ControllerPin: ctl.id.Pin.String(), Host: "h", Token: "tok",
		PlanKey: hex.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	r := startAgent(t, Config{Layout: l, HeartbeatInterval: 30 * time.Millisecond})
	eventually(t, 5*time.Second, "agent connected", func() bool { return ctl.send(&link.Ack{Seq: 0}) == nil })
	return ctl, priv, r
}

func safeModeSeen(ctl *fakeController) (on, off bool) {
	_, _, hbs := ctl.snapshot()
	if len(hbs) == 0 {
		return false, false
	}
	return hbs[len(hbs)-1].SafeMode, !hbs[len(hbs)-1].SafeMode
}

func refusals(ctl *fakeController) string {
	var b strings.Builder
	for _, f := range ctl.eventsOf("agent.control_refused") {
		fmt.Fprint(&b, f["reason"], "|")
	}
	return b.String()
}

// A control is acted on only if it is signed by the plan key, for this host,
// inside its window and with a fresh sequence number; everything else is refused.
func TestControlsAreVerified(t *testing.T) {
	ctl, priv, _ := startWithKey(t)
	sg := &plan.ControlSigner{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	issue := func(sg *plan.ControlSigner, host string, on bool) *plan.Control {
		c, err := sg.Issue(host, plan.ControlSafeMode, on, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	waitRefused := func(substr string) {
		t.Helper()
		eventually(t, 5*time.Second, "refusal "+substr, func() bool { return strings.Contains(refusals(ctl), substr) })
	}
	mode := func(want bool) {
		t.Helper()
		eventually(t, 5*time.Second, fmt.Sprintf("safe mode %v", want), func() bool {
			on, off := safeModeSeen(ctl)
			return (want && on) || (!want && off)
		})
	}

	on := issue(sg, "h", true)
	if err := ctl.send(plan.ControlToWire(on)); err != nil {
		t.Fatal(err)
	}
	mode(true)
	off := issue(sg, "h", false)
	ctl.send(plan.ControlToWire(off))
	mode(false)

	// Replay of the captured "on": refused, safe mode stays off.
	ctl.send(plan.ControlToWire(on))
	waitRefused("sequence")
	time.Sleep(150 * time.Millisecond)
	if m, _ := safeModeSeen(ctl); m {
		t.Fatal("a replayed control took effect")
	}

	// Forged: signed by some other key.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	ctl.send(plan.ControlToWire(issue(&plan.ControlSigner{Key: rogue, Epoch: 1, Seqs: &plan.MemSeq{}}, "h", true)))
	waitRefused("bad signature")
	// Tampered after signing (flip the flag, keep the signature).
	tam := issue(sg, "h", false)
	tam.On = true
	ctl.send(plan.ControlToWire(tam))
	eventually(t, 5*time.Second, "second bad signature", func() bool { return strings.Count(refusals(ctl), "bad signature") >= 2 })
	// Expired: correctly signed but its window ended ten minutes ago.
	old := &plan.ControlSigner{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}, Now: func() time.Time { return time.Now().Add(-10 * time.Minute) }}
	old.Seqs.(*plan.MemSeq).Next("h", 1) // keep numbering plausible
	for i := 0; i < 5; i++ {
		old.Seqs.(*plan.MemSeq).Next("h", 1)
	}
	ctl.send(plan.ControlToWire(issue(old, "h", true)))
	waitRefused("expired")
	// Wrong host.
	ctl.send(plan.ControlToWire(issue(sg, "other-host", true)))
	waitRefused("different host")
	// Unsigned.
	ctl.send(&link.Control{V: 1, Host: "h", Kind: "safe_mode", On: true, Epoch: 1, Seq: 99, NotBefore: time.Now().Unix(),
		NotAfter: time.Now().Add(time.Minute).Unix(), Sig: []byte("not a signature")})
	eventually(t, 5*time.Second, "third bad signature", func() bool { return strings.Count(refusals(ctl), "signature") >= 3 })

	time.Sleep(150 * time.Millisecond)
	if m, _ := safeModeSeen(ctl); m {
		t.Fatalf("a refused control took effect; refusals: %s", refusals(ctl))
	}
	// A good control after all the noise still works (the mark moved only for accepted ones).
	ctl.send(plan.ControlToWire(issue(sg, "h", true)))
	mode(true)
}

// Without a plan key in the bootstrap no control is ever accepted.
func TestControlRefusedWithoutPlanKey(t *testing.T) {
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok")
	startAgent(t, Config{Layout: l, HeartbeatInterval: 30 * time.Millisecond})
	eventually(t, 5*time.Second, "connected", func() bool { return ctl.send(&link.Ack{}) == nil })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := (&plan.ControlSigner{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}).Issue("h", plan.ControlSafeMode, true, nil)
	ctl.send(plan.ControlToWire(c))
	eventually(t, 5*time.Second, "refusal", func() bool { return strings.Contains(refusals(ctl), "no plan-signing key") })
}
