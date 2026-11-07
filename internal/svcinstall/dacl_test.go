package svcinstall

import (
	"strings"
	"testing"
)

// TestServiceSDDLShape checks the DACL's shape on any platform: the rights are
// the intent of design gap 5 (a hardened service that does not lock the
// operator out), and a typo in the string would only show up on Windows.
func TestServiceSDDLShape(t *testing.T) {
	s := ServiceSDDL
	if !strings.HasPrefix(s, "D:") {
		t.Fatalf("SDDL does not start with a DACL: %q", s)
	}
	// SYSTEM: every service right (SY owns the object, so it needs no WD).
	if !strings.Contains(s, "(A;;CCDCLCSWRPWPDTLOCRRC;;;SY)") {
		t.Errorf("SYSTEM has no full-control ACE: %q", s)
	}
	// Deny before the allows: change config (DC), stop (WP), pause (DT) and
	// delete (SD) for administrators, interactive, service and batch logons.
	for _, sid := range []string{"BA", "IU", "SU", "BU"} {
		if !strings.Contains(s, "(D;;DCWPDTSD;;;"+sid+")") {
			t.Errorf("no deny-stop ACE for %s: %q", sid, s)
		}
	}
	// The DACL grants WRITE_DAC (WD) to administrators only: that is the
	// break-glass `sc sdset` path, so it must not leak to a wider group.
	dacl, sacl, ok := strings.Cut(s, "S:(")
	if !ok {
		t.Fatalf("no SACL: %q", s)
	}
	wd := strings.Index(dacl, "WD")
	if wd < 0 || strings.Count(dacl, "WD") != 1 {
		t.Fatalf("WRITE_DAC is not granted exactly once in the DACL: %q", dacl)
	}
	if ace := dacl[:wd+strings.Index(dacl[wd:], ")")+1]; !strings.HasSuffix(ace, ";;;BA)") {
		t.Errorf("WRITE_DAC granted to more than administrators: %q", ace)
	}
	// Interactive, service and batch logons may query and start.
	for _, sid := range []string{"BA", "IU", "SU", "BU"} {
		ace, ok := allowACE(dacl, sid)
		if !ok {
			t.Fatalf("no allow ACE for %s: %q", sid, dacl)
		}
		mask := ace[strings.Index(ace, ";;")+2:]
		mask = mask[:strings.Index(mask, ";;")]
		if !strings.Contains(mask, "RP") || !strings.Contains(mask, "LC") {
			t.Errorf("%s may not start and query (mask %q, RP start, LC query status)", sid, mask)
		}
	}
	if !strings.HasPrefix(sacl, "AU;FA;") {
		t.Errorf("the SACL does not audit failed access by everyone: %q", sacl)
	}
	if len(s) >= 400 {
		t.Errorf("SDDL is %d characters; the limit is 400", len(s))
	}
}

// allowACE returns the allow ACE for sid, e.g. "(A;;CCLC;;;IU)".
func allowACE(dacl, sid string) (string, bool) {
	for _, ace := range strings.Split(dacl, ")") {
		ace += ")"
		if strings.HasPrefix(ace, "(A;;") && strings.HasSuffix(ace, ";;;"+sid+")") {
			return ace, true
		}
	}
	return "", false
}

func TestWatchdogStallExitsAfterThreeChecks(t *testing.T) {
	var n int
	var exit bool
	if exit, n = stallCounter([]string{"heartbeat"}, n); exit || n != 1 {
		t.Fatalf("first stalled check: exit %v, n %d", exit, n)
	}
	if exit, n = stallCounter([]string{"heartbeat"}, n); exit || n != 2 {
		t.Fatalf("second stalled check: exit %v, n %d", exit, n)
	}
	if exit, n = stallCounter([]string{"heartbeat", "modules"}, n); !exit {
		t.Fatalf("third stalled check did not exit: n %d", n)
	}
	// A healthy check resets the count, and a later run of stalls starts over.
	if exit, n = stallCounter(nil, 2); exit || n != 0 {
		t.Fatalf("healthy check: exit %v, n %d", exit, n)
	}
	if exit, n = stallCounter([]string{"config"}, n); exit || n != 1 {
		t.Fatalf("stall after a reset: exit %v, n %d", exit, n)
	}
}
