package winevt

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
)

func TestSysvolPolicyFields(t *testing.T) {
	g := "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	cases := []struct {
		path, item, section string
		match               bool
	}{
		{`C:\Windows\SYSVOL\domain\Policies\` + g + `\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml`, "gpp_scheduledtasks", "machine", true},
		{`C:\Windows\SYSVOL\sysvol\ccdc.local\Policies\` + g + `\User\Preferences\Groups\Groups.xml`, "gpp_groups", "user", true},
		{`\\dc01\SYSVOL\ccdc.local\Policies\` + g + `\Machine\Scripts\Startup\x.bat`, "scripts", "machine", true},
		{`C:\Windows\SYSVOL\domain\Policies\` + g + `\Machine\Registry.pol`, "registry_pol", "machine", true},
		{`C:\Windows\SYSVOL\domain\Policies\` + g + `\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, "security_template", "machine", true},
		{`C:\Windows\SYSVOL\domain\scripts\logon.bat`, "", "", false},
		{`C:\Users\a\Policies\` + g + `\x`, "", "", false},
	}
	for _, c := range cases {
		f := map[string]any{}
		sysvolPolicyFields(f, c.path)
		if (f["sysvol_policy"] == true) != c.match {
			t.Errorf("%s: sysvol_policy=%v", c.path, f["sysvol_policy"])
			continue
		}
		if c.match && (f["gpo_item"] != c.item || f["gpo_section"] != c.section || f["gpo_guid"] != g) {
			t.Errorf("%s: %v", c.path, f)
		}
	}
}

func TestGPOObjectFields(t *testing.T) {
	f := map[string]any{}
	gpoObjectFields(f, "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=ccdc,DC=local", "groupPolicyContainer")
	if f["gpo"] != true || f["gpo_guid"] != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Fatalf("%v", f)
	}
	f = map[string]any{}
	gpoObjectFields(f, "CN=Users,DC=ccdc,DC=local", "container")
	if len(f) != 0 {
		t.Fatalf("non-GPO object marked: %v", f)
	}
}

func TestMapperAddsGPOFields(t *testing.T) {
	e := mapOne(t, &Mapper{}, "sec5137")
	if e.Fields["gpo"] != true {
		t.Fatalf("5137 groupPolicyContainer not marked: %v", e.Fields)
	}
}

// The producer's real output must trip the shipped rule (guards field-name drift).
func TestMappedGPOEventFiresRule(t *testing.T) {
	rs, err := detect.LoadDir("../../../rules", detect.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e := mapOne(t, &Mapper{}, "sec5137")
	e.Agent = "dc01"
	var hit bool
	for _, a := range detect.NewEngine(rs, detect.Options{}).Process(e) {
		hit = hit || a.RuleID == "D6v.sysvol-gpp-change"
	}
	if !hit {
		t.Fatalf("D6v did not fire on the mapped 5137 event: %v", e.Fields)
	}
}
