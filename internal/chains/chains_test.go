package chains

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/traceback/tbtest"
)

var t0 = time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)

const sec = time.Second

const (
	attacker = "198.51.100.7"
	webIP    = "10.0.1.10"
	dcIP     = "10.0.1.5"
)

func hopOf(c *Chain, kind Kind, contains string) *Hop {
	for i := range c.Hops {
		h := &c.Hops[i]
		if h.Kind == kind && (strings.Contains(h.What, contains) || strings.Contains(h.Path, contains)) {
			return h
		}
	}
	return nil
}

func causeOf(c *Chain, h *Hop) *Hop {
	if h == nil || h.Cause < 0 {
		return nil
	}
	return &c.Hops[h.Cause]
}

func inbound(pid, ticks int, raddr string, rport int, cid string) map[string]any {
	return map[string]any{"dir": "inbound", "proto": "tcp", "laddr": webIP, "lport": 80, "raddr": raddr, "rport": rport,
		"service": "http", "community_id": cid, "pid": pid, "pid_start": ticks, "comm": "apache2", "exe": "/usr/sbin/apache2"}
}

// webshellFixture: red-team-ttps web-app compromise on ecom.
func webshellFixture(t *testing.T) (*tbtest.Fixture, event.Event) {
	f := tbtest.New(t, t0)
	f.Add("ecom", 100*sec, "net.connection_opened", inbound(800, 5000, attacker, 51000, "1:abc"))
	f.Add("ecom", 100*sec+200*time.Millisecond, "process_start", map[string]any{
		"pid": 901, "ppid": 800, "exe": "/bin/sh", "cmdline": "sh -c echo '<?php system($_GET[1]);' > uploads/x.php",
		"start_ticks": 5100, "parent": map[string]any{"pid": 800, "exe": "/usr/sbin/apache2"}, "pexe": "/usr/sbin/apache2"})
	ev := f.Add("ecom", 100*sec+400*time.Millisecond, "file_change", map[string]any{
		"op": "create", "path": "/var/www/html/uploads/x.php", "pid": 901, "exe": "/bin/sh", "writer_start_ticks": 5100, "source": "audit"})
	return f, ev
}

func TestWebshellChain(t *testing.T) {
	f, ev := webshellFixture(t)
	b := &Builder{Src: f.Store}
	c, err := b.Build(f.Ctx, Seed{Kind: SeedServiceChange, Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Hops) != 3 {
		t.Fatalf("hops = %d: %+v", len(c.Hops), c.Hops)
	}
	ch := hopOf(c, Change, "x.php")
	ex := hopOf(c, Exec, "sh -c")
	ac := hopOf(c, Access, attacker)
	if ch == nil || ex == nil || ac == nil {
		t.Fatalf("missing hops: %v %v %v", ch, ex, ac)
	}
	if !ch.Seed || ch.Technique != "T1505.003" || ex.Technique != "T1059.004" || ac.Technique != "T1190" {
		t.Errorf("seed/techniques: %v %v %v %v", ch.Seed, ch.Technique, ex.Technique, ac.Technique)
	}
	if causeOf(c, ch) != ex || causeOf(c, ex) != ac || ac.Cause != -1 {
		t.Errorf("cause links wrong: change<-%d exec<-%d access<-%d", ch.Cause, ex.Cause, ac.Cause)
	}
	if ex.Method != MethodLineage || ex.Confidence < 0.7 || ex.Confidence >= 1 {
		t.Errorf("exec link %s %.2f", ex.Method, ex.Confidence)
	}
	if ac.CommunityID != "1:abc" || ac.Service != "http" || ac.SrcAddr != attacker {
		t.Errorf("access hop %+v", ac)
	}
	// Remediation: close entry, block source, remove the webshell.
	kinds := map[ItemKind]bool{}
	for _, h := range c.Hops {
		for _, it := range h.Items {
			kinds[it.Kind] = true
			if it.Verified() {
				t.Errorf("item verified at birth: %+v", it)
			}
		}
	}
	for _, k := range []ItemKind{CloseEntry, BlockSource, RemoveArtifact} {
		if !kinds[k] {
			t.Errorf("no %s item", k)
		}
	}
	if c.Confidence != ex.Confidence {
		t.Errorf("chain confidence %.2f, weakest hop %.2f", c.Confidence, ex.Confidence)
	}
}

func TestAgentGapLowersConfidence(t *testing.T) {
	f, ev := webshellFixture(t)
	f.Gap("ecom", 105*sec, 30)
	b := &Builder{Src: f.Store}
	c, err := b.Build(f.Ctx, Seed{Kind: SeedServiceChange, Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range c.Hops {
		if h.Confidence > 0.61 {
			t.Errorf("hop %d (%s) confidence %.2f not lowered by the gap", h.Ord, h.Kind, h.Confidence)
		}
		found := false
		for _, n := range h.Notes {
			if strings.Contains(n, "agent gap on ecom") && strings.Contains(n, "30 events lost") {
				found = true
			}
		}
		if !found {
			t.Errorf("hop %d lacks the gap note: %v", h.Ord, h.Notes)
		}
	}
	if c.Confidence > 0.61 || len(c.Notes) == 0 {
		t.Errorf("chain confidence %.2f notes %v", c.Confidence, c.Notes)
	}
	rows := c.Timeline(time.UTC)
	for _, r := range rows {
		if r.Level != "low" && r.Level != "medium" {
			t.Errorf("row level %s", r.Level)
		}
	}
}

// lateralFixture: default-cred SSH on web -> sudo -> cron persistence ->
// WinRM to the DC with a new hidden domain admin.
func lateralFixture(t *testing.T) (*tbtest.Fixture, event.Event, event.Event) {
	f := tbtest.New(t, t0)
	for i := 0; i < 6; i++ {
		f.Add("web", time.Duration(i)*sec, "auth_fail", map[string]any{"account": "admin", "source": attacker, "service": "ssh", "source_port": "50000"})
	}
	f.Add("web", 10*sec, "auth_success", map[string]any{"account": "admin", "source": attacker, "service": "ssh", "method": "password"})
	f.Add("web", 10*sec+100*time.Millisecond, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": webIP, "lport": 22,
		"raddr": attacker, "rport": 50022, "service": "ssh", "community_id": "1:ssh", "pid": 700, "pid_start": 100, "comm": "sshd", "exe": "/usr/sbin/sshd"})
	f.Add("web", 12*sec, "process_start", map[string]any{"pid": 710, "ppid": 700, "exe": "/bin/bash", "cmdline": "-bash", "start_ticks": 111,
		"parent": map[string]any{"pid": 700, "exe": "/usr/sbin/sshd"}, "pexe": "/usr/sbin/sshd"})
	f.Add("web", 20*sec, "process_start", map[string]any{"pid": 720, "ppid": 710, "exe": "/usr/bin/sudo", "cmdline": "sudo -s", "start_ticks": 120})
	f.Add("web", 21*sec, "process_start", map[string]any{"pid": 721, "ppid": 720, "exe": "/bin/bash", "cmdline": "bash", "start_ticks": 122})
	cron := f.Add("web", 40*sec, "file_change", map[string]any{"op": "create", "path": "/etc/cron.d/backup", "pid": 721, "exe": "/bin/bash", "writer_start_ticks": 122, "source": "audit"})
	f.Add("web", 60*sec, "process_start", map[string]any{"pid": 730, "ppid": 721, "exe": "/usr/bin/python3", "cmdline": "python3 /tmp/.w/winrm.py dc", "start_ticks": 130})
	web, dc := netip.MustParseAddr(webIP), netip.MustParseAddr(dcIP)
	cid := netmod.CommunityID(0, netmod.ProtoTCP, netip.AddrPortFrom(web, 44000), netip.AddrPortFrom(dc, 5985))
	f.Add("web", 61*sec, "net.connection_opened", map[string]any{"dir": "outbound", "proto": "tcp", "laddr": webIP, "lport": 44000,
		"raddr": dcIP, "rport": 5985, "service": "winrm", "community_id": cid, "pid": 730, "pid_start": 130, "exe": "/usr/bin/python3"})
	// The DC: Sysmon 3 inbound (owned by System/http.sys, pid 4), the 4624, then the hidden DA.
	f.Add("dc", 61*sec+200*time.Millisecond, "net_connect", map[string]any{"dir": "in", "proto": "tcp", "src_ip": webIP, "src_port": 44000,
		"dst_ip": dcIP, "dst_port": 5985, "initiated": false, "pid": 4, "sensor": "sysmon"})
	f.Add("dc", 61*sec+500*time.Millisecond, "auth_success", map[string]any{"account": "svc_backup", "domain": "CORP", "source": webIP, "source_port": "44000",
		"service": "windows", "method": "Kerberos", "logon_type": 3, "logon_type_name": "network"})
	f.Add("dc", 63*sec, "process_start", map[string]any{"pid": 3000, "ppid": 900, "exe": `C:\Windows\System32\wsmprovhost.exe`, "cmdline": "wsmprovhost.exe -Embedding",
		"user": `CORP\svc_backup`, "sensor": "sysmon", "sha256": "aa11"})
	f.Add("dc", 70*sec, "process_start", map[string]any{"pid": 3010, "ppid": 3000, "exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"cmdline": "powershell net user hidden_da P@ss /add /domain", "user": `CORP\svc_backup`, "sensor": "sysmon"})
	f.Add("dc", 72*sec, "sec_event", map[string]any{"category": "account_change", "op": "created", "account": "hidden_da", "subject_account": `CORP\svc_backup`})
	grp := f.Add("dc", 73*sec, "sec_event", map[string]any{"category": "group_change", "op": "member_added", "group_name": "Domain Admins",
		"member_name": "hidden_da", "subject_account": `CORP\svc_backup`})
	return f, grp, cron
}

func TestLateralChainAcrossHostsOneCampaign(t *testing.T) {
	f, grp, cron := lateralFixture(t)
	b := &Builder{Src: f.Store}
	alert := detect.Alert{RuleID: "D9.da-group-add", Severity: "high", Attack: []string{"T1098"}, Agent: "dc", Time: grp.Time, Evidence: []event.Event{grp}, Message: "Domain Admins membership changed"}
	seed, ok := SeedFromAlert(alert)
	if !ok {
		t.Fatal("high alert must seed")
	}
	c, err := b.Build(f.Ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Hops) < 9 || len(c.Hops) > 12 || c.Truncated {
		t.Fatalf("hops=%d truncated=%v", len(c.Hops), c.Truncated)
	}
	mv := hopOf(c, Move, "")
	if mv == nil || mv.SrcHost != "web" || mv.DstHost != "dc" {
		t.Fatalf("move hop = %+v", mv)
	}
	if mv.Method != MethodCommunityID || mv.Confidence != 0.95 || mv.Technique != "T1021.006" || mv.Account != "svc_backup" {
		t.Errorf("move: method=%s conf=%.2f tech=%s acct=%s", mv.Method, mv.Confidence, mv.Technique, mv.Account)
	}
	py := causeOf(c, mv)
	if py == nil || py.Kind != Exec || py.Host() != "web" || !strings.Contains(py.What, "winrm.py") {
		t.Fatalf("move cause = %+v", py)
	}
	// The web side: python <- bash(root) <- sudo <- bash <- access (admin from the attacker, brute-forced).
	cur, depth := py, 0
	for cur != nil && cur.Kind != Access {
		cur = causeOf(c, cur)
		depth++
	}
	if cur == nil || cur.Account != "admin" || cur.SrcAddr != attacker || cur.Technique != "T1110" || depth != 4 {
		t.Fatalf("web ancestry: access=%+v depth=%d", cur, depth)
	}
	sudo := hopOf(c, Exec, "sudo -s")
	if sudo == nil || sudo.Technique != "T1548.003" {
		t.Errorf("sudo hop %+v", sudo)
	}
	cr := hopOf(c, Change, "/etc/cron.d/backup")
	if cr == nil || !cr.Persistence || cr.Technique != "T1053.003" {
		t.Errorf("cron hop %+v", cr)
	}
	// The DC side: wsmprovhost and powershell under the move; DA changes linked by account.
	ps := hopOf(c, Exec, "net user hidden_da")
	if ps == nil || ps.Account != "svc_backup" {
		t.Fatalf("powershell hop %+v", ps)
	}
	if w := causeOf(c, ps); w == nil || !strings.Contains(w.What, "wsmprovhost") {
		t.Errorf("powershell cause %+v", w)
	}
	seedHop := c.SeedHop()
	if seedHop == nil || seedHop.Technique != "T1098" || seedHop.Path != "group:Domain Admins+hidden_da" {
		t.Fatalf("seed hop %+v", seedHop)
	}
	if causeOf(c, seedHop) != mv || seedHop.Method != MethodSameAccount {
		t.Errorf("seed cause method %s", seedHop.Method)
	}
	acc := hopOf(c, Change, "account:hidden_da")
	if acc == nil || acc.Technique != "T1136.002" {
		t.Errorf("account hop %+v", acc)
	}
	if c.Confidence != 0.6 {
		t.Errorf("chain confidence %.2f (weakest is the same-account link)", c.Confidence)
	}
	// Timeline view model.
	rows := c.Timeline(Central())
	if len(rows) != len(c.Hops) {
		t.Fatal("one row per hop")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].Time.Before(rows[i-1].Time) {
			t.Fatal("rows not in time order")
		}
	}
	var mvRow Row
	for _, r := range rows {
		if r.Kind == Move {
			mvRow = r
		}
	}
	if mvRow.Host != "web -> dc" || mvRow.UTC == "" || !strings.Contains(mvRow.Local, "CST") {
		t.Errorf("move row %+v", mvRow)
	}

	// A second chain seeded on the web side shares the source and account: one campaign.
	c2, err := b.Build(f.Ctx, Seed{Kind: SeedServiceChange, Event: &cron})
	if err != nil {
		t.Fatal(err)
	}
	camps := Group([]*Chain{c, c2}, Config{})
	if len(camps) != 1 || len(camps[0].Chains) != 2 {
		t.Fatalf("campaigns = %d", len(camps))
	}
	k := camps[0].Keys
	if len(k.Sources) != 1 || k.Sources[0] != attacker || !contains(k.Accounts, "svc_backup") || !contains(k.Accounts, "admin") {
		t.Errorf("keys %+v", k)
	}
	// An unrelated chain stays apart.
	f2, ev2 := webshellFixture(t)
	other, err := (&Builder{Src: f2.Store}).Build(f2.Ctx, Seed{Event: &ev2})
	if err != nil {
		t.Fatal(err)
	}
	other.Hops[0].SrcAddr = "192.0.2.77"
	for i := range other.Hops {
		other.Hops[i].Account = ""
	}
	if camps := Group([]*Chain{c, c2, other}, Config{}); len(camps) != 2 {
		t.Fatalf("expected 2 campaigns, got %d", len(camps))
	}
	// And a shared binary hash merges otherwise unrelated chains.
	other.Hops[1].Proc.SHA256 = "aa11"
	if camps := Group([]*Chain{c, other}, Config{}); len(camps) != 1 {
		t.Fatalf("hash grouping: %d campaigns", len(camps))
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRemediationListAndVerification(t *testing.T) {
	f, grp, _ := lateralFixture(t)
	b := &Builder{Src: f.Store}
	c, err := b.Build(f.Ctx, Seed{Kind: SeedAlert, Event: &grp})
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		k ItemKind
		t string
	}
	have := map[key]Item{}
	for _, h := range c.Hops {
		for _, it := range h.Items {
			if _, dup := have[key{it.Kind, it.Target}]; dup {
				t.Errorf("duplicate item %s %s", it.Kind, it.Target)
			}
			have[key{it.Kind, it.Target}] = it
		}
	}
	for _, want := range []key{
		{BlockSource, attacker}, {RotateCredential, "admin"}, {RotateCredential, "svc_backup"},
		{RemovePersistence, "/etc/cron.d/backup"}, {RemovePersistence, "account:hidden_da"},
		{RemovePersistence, "group:Domain Admins+hidden_da"},
	} {
		if _, ok := have[want]; !ok {
			t.Errorf("missing item %v", want)
		}
	}
	var entries int
	for k := range have {
		if k.k == CloseEntry {
			entries++
		}
	}
	if entries < 2 { // ssh entry on web and the winrm path web->dc
		t.Errorf("close_entry items = %d", entries)
	}

	// Nothing verifies before the fix.
	n, err := b.Verify(f.Ctx, c)
	if err != nil || n != 0 {
		t.Fatalf("verify before fix: %d %v", n, err)
	}
	// The team rotates admin, resets svc_backup, deletes the cron file and removes the group member.
	f.Add("web", 3600*sec, "sec_event", map[string]any{"category": "account_change", "op": "password_reset", "account": "admin"})
	f.Add("dc", 3601*sec, "sec_event", map[string]any{"category": "account_change", "op": "password_reset", "account": "svc_backup", "subject_account": `CORP\Administrator`})
	f.Add("web", 3602*sec, "file_change", map[string]any{"op": "delete", "path": "/etc/cron.d/backup", "pid": 4000, "exe": "/bin/rm"})
	f.Add("dc", 3603*sec, "sec_event", map[string]any{"category": "group_change", "op": "member_removed", "group_name": "Domain Admins", "member_name": "hidden_da"})
	n, err = b.Verify(f.Ctx, c)
	if err != nil || n != 4 {
		t.Fatalf("verify after fix: %d %v", n, err)
	}
	for _, h := range c.Hops {
		for _, it := range h.Items {
			want := (it.Kind == RotateCredential && (it.Target == "admin" || it.Target == "svc_backup")) ||
				it.Target == "/etc/cron.d/backup" || it.Target == "group:Domain Admins+hidden_da"
			if it.Verified() != want {
				t.Errorf("%s %s verified=%v want %v (%s)", it.Kind, it.Target, it.Verified(), want, it.Note)
			}
		}
	}
	if sec := c.IRSection(Central()); sec.ProofClosed || len(sec.Remediation) == 0 || len(sec.Techniques) == 0 {
		t.Errorf("IR section: closed=%v items=%d", sec.ProofClosed, len(sec.Remediation))
	}

	// Persist, reload, update states.
	ctx := context.Background()
	if err := Save(ctx, f.Store, c); err != nil {
		t.Fatal(err)
	}
	if err := SaveItemStates(ctx, f.Store, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ctx, f.Store, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hops) != len(c.Hops) || got.Confidence != c.Confidence || got.Seed != SeedAlert {
		t.Fatalf("reload: %d hops conf %.2f seed %s", len(got.Hops), got.Confidence, got.Seed)
	}
	for i := range got.Hops {
		a, b := got.Hops[i], c.Hops[i]
		if a.Kind != b.Kind || a.Cause != b.Cause || a.What != b.What || a.Method != b.Method || len(a.Items) != len(b.Items) || !a.Start.Equal(b.Start) {
			t.Fatalf("hop %d differs:\n%+v\n%+v", i, a, b)
		}
		for j := range a.Items {
			if a.Items[j].State != b.Items[j].State || a.Items[j].Target != b.Items[j].Target {
				t.Fatalf("item differs: %+v vs %+v", a.Items[j], b.Items[j])
			}
		}
	}
	camps, err := SyncCampaigns(ctx, f.Store, []*Chain{got}, Config{})
	if err != nil || len(camps) != 1 || camps[0].ID == 0 || got.CampaignID != camps[0].ID {
		t.Fatalf("sync: %v %+v", err, camps)
	}
	rows, _ := f.Store.Campaigns(ctx)
	if len(rows) != 1 || !strings.Contains(rows[0].Name, attacker) {
		t.Errorf("campaign rows %+v", rows)
	}
	all, err := LoadAll(ctx, f.Store)
	if err != nil || len(all) != 1 || all[0].CampaignID != camps[0].ID {
		t.Fatalf("load all: %v", err)
	}
}

func TestBoundsRespected(t *testing.T) {
	f, grp, _ := lateralFixture(t)
	// The same source touched mail 1 h before and 3 h before the seed.
	f.Add("mail", -3600*sec, "auth_success", map[string]any{"account": "postmaster", "source": attacker, "service": "imap"})
	f.Add("mail", -3*3600*sec, "auth_success", map[string]any{"account": "olduser", "source": attacker, "service": "imap"})
	b := &Builder{Src: f.Store}
	c, err := b.Build(f.Ctx, Seed{Event: &grp})
	if err != nil {
		t.Fatal(err)
	}
	if hopOf(c, Access, "mail") == nil {
		t.Error("backward expansion should find the source's earlier login (1 h)")
	}
	for _, h := range c.Hops {
		if h.Account == "olduser" {
			t.Errorf("hop outside the 2 h window included: %+v", h)
		}
		if h.Start.Before(grp.Time.Add(-2*time.Hour)) || h.Start.After(grp.Time.Add(2*time.Hour)) {
			t.Errorf("hop outside the bound: %v", h.Start)
		}
	}
	// A narrower window drops the 1 h hop.
	b2 := &Builder{Src: f.Store, Cfg: Config{Window: 30 * time.Minute}}
	c, err = b2.Build(f.Ctx, Seed{Event: &grp})
	if err != nil {
		t.Fatal(err)
	}
	if hopOf(c, Access, "mail") != nil {
		t.Error("30 min window should exclude the earlier login")
	}
	// Hop limit.
	b3 := &Builder{Src: f.Store, Cfg: Config{MaxHops: 4}}
	c, err = b3.Build(f.Ctx, Seed{Event: &grp})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Hops) != 4 || !c.Truncated || c.SeedHop() == nil {
		t.Fatalf("hops=%d truncated=%v seed=%v", len(c.Hops), c.Truncated, c.SeedHop())
	}
	if !strings.Contains(strings.Join(c.Notes, " "), "hop limit 4") {
		t.Errorf("notes %v", c.Notes)
	}
	for _, h := range c.Hops {
		if h.Cause >= len(c.Hops) {
			t.Errorf("dangling cause %d", h.Cause)
		}
	}
}

func TestSeedWithoutSessionGraftsTimeWindowGuess(t *testing.T) {
	f := tbtest.New(t, t0)
	// php-fpm style: nothing ties the writer to a socket; two clients arrived around it.
	for i, a := range []string{attacker, "203.0.113.9"} {
		f.Add("web", time.Duration(10+i)*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": webIP, "lport": 80,
			"raddr": a, "rport": 4000 + i, "service": "http", "community_id": "1:x" + a})
	}
	ev := f.Add("web", 12*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 55, "exe": "/bin/sh"})
	c, err := (&Builder{Src: f.Store}).Build(f.Ctx, Seed{Kind: SeedServiceChange, Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	ch := c.SeedHop()
	ac := causeOf(c, ch)
	if ac == nil || ac.Kind != Access || ch.Method != MethodTimeWindow || ch.Confidence > 0.3 {
		t.Fatalf("seed %+v cause %+v", ch, ac)
	}
	rows := c.Timeline(time.UTC)
	if !rows[len(rows)-1].Guess || rows[len(rows)-1].Level != "low" {
		t.Errorf("guess not flagged: %+v", rows)
	}
	// A seed with no explanation at all says so rather than inventing one.
	f2 := tbtest.New(t, t0)
	ev = f2.Add("web", 12*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 55, "exe": "/bin/sh"})
	c, err = (&Builder{Src: f2.Store}).Build(f2.Ctx, Seed{Event: &ev})
	if err != nil || len(c.Hops) != 1 {
		t.Fatalf("%v %d", err, len(c.Hops))
	}
	if !strings.Contains(strings.Join(c.Hops[0].Notes, " "), "chain breaks at") {
		t.Errorf("notes %v", c.Hops[0].Notes)
	}
}

func TestOwnTrafficAndTaggedActivityExcluded(t *testing.T) {
	f, ev := webshellFixture(t)
	// The scorer also logged in; our own plan changed a file.
	f.Add("ecom", 90*sec, "auth_success", map[string]any{"account": "scorer", "source": "10.9.9.9", "service": "http"})
	f.Add("ecom", 101*sec, "file_change", map[string]any{"op": "write", "path": "/etc/apache2/ours.conf", "pid": 901, "exe": "/bin/sh", "tag": "plan-3"})
	b := &Builder{Src: f.Store, Cfg: Config{Label: func(a string) string {
		if a == "10.9.9.9" {
			return "scorer"
		}
		return ""
	}}}
	c, err := b.Build(f.Ctx, Seed{Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range c.Hops {
		if h.Account == "scorer" || strings.Contains(h.Path, "ours.conf") {
			t.Errorf("own or scorer activity in the chain: %+v", h)
		}
	}
}

func TestSeedFromAlertQualification(t *testing.T) {
	if _, ok := SeedFromAlert(detect.Alert{RuleID: "D3.new-listener", Severity: "medium"}); ok {
		t.Error("medium alert must not seed")
	}
	for id, want := range map[string]SeedKind{"D12.decoy-hit": SeedDecoy, "D13.honeytoken-use": SeedHoneytoken, "I1.ledger-mismatch": SeedLedger} {
		s, ok := SeedFromAlert(detect.Alert{RuleID: id, Severity: "low"})
		if !ok || s.Kind != want {
			t.Errorf("%s: %v %v", id, ok, s.Kind)
		}
	}
	if s, ok := SeedFromAlert(detect.Alert{RuleID: "D1.service-spawns-shell", Severity: "critical"}); !ok || s.Kind != SeedAlert {
		t.Error("critical alert must seed")
	}
}

func TestNoSeedEvent(t *testing.T) {
	f := tbtest.New(t, t0)
	f.Add("web", 0, "heartbeat", map[string]any{})
	_, err := (&Builder{Src: f.Store}).Build(f.Ctx, Seed{Agent: "web", Time: t0})
	if err != ErrNoSeedEvent {
		t.Fatalf("err = %v", err)
	}
}
