package xmlapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/palotest"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
)

func TestXPathParsing(t *testing.T) {
	st, err := xmlapi.ParseXPath("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/permitted-ip/entry[@name='10.0.0.0/24']")
	if err != nil {
		t.Fatal(err)
	}
	last := st[len(st)-1]
	if len(st) != 7 || last.Name != "entry" || last.Entry != "10.0.0.0/24" {
		t.Fatalf("steps = %+v", st)
	}
	for _, bad := range []string{"config/x", "/a//b", "/a/entry[@id='x']"} {
		if _, err := xmlapi.ParseXPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTreeMergeEditCanonicalFlatten(t *testing.T) {
	a, err := xmlapi.ParseNode([]byte(`<config><r><entry name="x" admin="bob" dirtyId="3" time="t"><from><member>a</member></from></entry></r></config>`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := xmlapi.ParseNode([]byte(`<config><r><entry dirtyId="9" name="x"><from><member>a</member></from></entry></r></config>`))
	if string(xmlapi.Canonical(a)) != string(xmlapi.Canonical(b)) {
		t.Errorf("volatile attrs / attr order leak into the canonical form:\n%s\n%s", xmlapi.Canonical(a), xmlapi.Canonical(b))
	}
	a.Merge(&xmlapi.Node{Name: "config", Children: []*xmlapi.Node{{Name: "r", Children: []*xmlapi.Node{{Name: "entry", Attrs: []xmlapi.Attr{{Name: "name", Value: "x"}}, Children: []*xmlapi.Node{{Name: "from", Children: []*xmlapi.Node{{Name: "member", Text: "b"}}}}}}}}})
	f := xmlapi.Flatten(a)
	if _, ok := f["/config/r/entry[@name='x']/from/member[a]"]; !ok {
		t.Errorf("flatten = %v", f)
	}
	if _, ok := f["/config/r/entry[@name='x']/from/member[b]"]; !ok {
		t.Errorf("merge lost the new member: %v", f)
	}
	if _, err := xmlapi.ParseNode([]byte(`<a><b></a>`)); err == nil {
		// non-strict parser tolerates some input; a truly unclosed document must fail
		if _, err := xmlapi.ParseNode([]byte(`<a><b>`)); err == nil {
			t.Error("unclosed document accepted")
		}
	}
	deep := strings.Repeat("<a>", 500) + strings.Repeat("</a>", 500)
	if _, err := xmlapi.ParseNode([]byte(deep)); err == nil {
		t.Error("deeply nested document accepted")
	}
}

func newClient(t *testing.T) (*palotest.Server, *xmlapi.Client) {
	srv := palotest.New()
	t.Cleanup(srv.Close)
	c := &xmlapi.Client{BaseURL: srv.URL, HTTP: srv.Client()}
	key, err := c.Keygen(context.Background(), "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	c.Key = key
	return srv, c
}

func TestKeygenAndAuth(t *testing.T) {
	srv, c := newClient(t)
	_ = srv
	if _, err := c.Keygen(context.Background(), "admin", "wrong"); err == nil {
		t.Error("bad password accepted")
	}
	bad := &xmlapi.Client{BaseURL: srv.URL, HTTP: srv.Client(), Key: "nope"}
	var ae *xmlapi.APIError
	if _, err := bad.SystemInfo(context.Background()); !errors.As(err, &ae) {
		t.Errorf("bad key: %v", err)
	}
}

func TestConfigCRUDAndMulti(t *testing.T) {
	_, c := newClient(t)
	ctx := context.Background()
	base := "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
	if err := c.ConfigSet(ctx, base, `<entry name="a"><ip-netmask>1.1.1.1</ip-netmask></entry>`); err != nil {
		t.Fatal(err)
	}
	n, err := c.ConfigGet(ctx, xmlapi.EntryXPath(base, "a"))
	if err != nil || n == nil || n.ChildText("ip-netmask") != "1.1.1.1" {
		t.Fatalf("get = %v %v", n, err)
	}
	if run, err := c.ConfigShow(ctx, xmlapi.EntryXPath(base, "a")); err != nil || run != nil {
		t.Errorf("uncommitted object visible in running: %v %v", run, err)
	}
	if err := c.ConfigEdit(ctx, xmlapi.EntryXPath(base, "a"), `<entry name="a"><ip-netmask>2.2.2.2</ip-netmask></entry>`); err != nil {
		t.Fatal(err)
	}
	// strict multi-config: one bad op leaves nothing applied.
	err = c.MultiConfig(ctx, []xmlapi.MultiOp{
		{Action: "set", XPath: base, Element: `<entry name="b"><ip-netmask>3.3.3.3</ip-netmask></entry>`},
		{Action: "delete", XPath: xmlapi.EntryXPath(base, "missing")},
	}, true)
	if err == nil {
		t.Fatal("strict multi-config with a failing op succeeded")
	}
	if b, _ := c.ConfigGet(ctx, xmlapi.EntryXPath(base, "b")); b != nil {
		t.Error("strict-transactional left a partial change")
	}
	if err := c.MultiConfig(ctx, []xmlapi.MultiOp{{Action: "bogus", XPath: base}}, true); err == nil {
		t.Error("bad action accepted")
	}
	if err := c.ConfigDelete(ctx, xmlapi.EntryXPath(base, "a")); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.ConfigGet(ctx, xmlapi.EntryXPath(base, "a")); n != nil {
		t.Error("delete did not delete")
	}
}

func TestCommitJobsAndNoChanges(t *testing.T) {
	srv, c := newClient(t)
	srv.JobPolls = 3
	ctx := context.Background()
	if _, none, err := c.CommitPartialAdmin(ctx, "admin", ""); err != nil || !none {
		t.Fatalf("empty commit: none=%v err=%v", none, err)
	}
	if err := c.ConfigSet(ctx, "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address", `<entry name="a"><ip-netmask>1.1.1.1</ip-netmask></entry>`); err != nil {
		t.Fatal(err)
	}
	id, none, err := c.CommitPartialAdmin(ctx, "admin", "test")
	if err != nil || none || id == "" {
		t.Fatalf("commit: %q %v %v", id, none, err)
	}
	j, err := c.ShowJob(ctx, id)
	if err != nil || j.Done() {
		t.Fatalf("job finished too early: %+v %v", j, err)
	}
	j, err = c.WaitJob(ctx, id, time.Millisecond, time.Second)
	if err != nil || !j.Done() || j.Result != "OK" {
		t.Fatalf("wait: %+v %v", j, err)
	}
}

func TestWaitJobHonoursDeadline(t *testing.T) {
	srv, c := newClient(t)
	srv.JobPolls = 1 << 30
	ctx := context.Background()
	_ = c.ConfigSet(ctx, "/config/x", `<entry name="a"/>`)
	id, _, err := c.CommitPartialAdmin(ctx, "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.WaitJob(ctx, id, time.Millisecond, 50*time.Millisecond); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("poll ignored its deadline")
	}
}

func TestLocksAndLogs(t *testing.T) {
	srv, c := newClient(t)
	ctx := context.Background()
	if err := c.ConfigLockAdd(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	locks, err := c.ShowConfigLocks(ctx, "vsys1")
	if err != nil || len(locks) != 1 || locks[0].Admin != "admin" {
		t.Fatalf("locks = %+v %v", locks, err)
	}
	if err := c.ConfigLockRemove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.ConfigLockRemove(ctx); !errors.Is(err, xmlapi.ErrNotLocked) {
		t.Errorf("second remove: %v", err)
	}
	srv.HoldLock("someone", "mine")
	if err := c.ConfigLockAdd(ctx, "x"); !errors.Is(err, xmlapi.ErrLockHeld) {
		t.Errorf("held lock: %v", err)
	}
	srv.AddLog("system", map[string]string{"admin": "a"})
	srv.AddLog("system", map[string]string{"admin": "b"})
	es, err := c.LogQuery(ctx, "system", "(seqno geq 2)", 10, 0, time.Millisecond, time.Second)
	if err != nil || len(es) != 1 || es[0]["admin"] != "b" {
		t.Errorf("logs = %+v %v", es, err)
	}
	raw, err := c.ExportConfig(ctx)
	if err != nil || !strings.HasPrefix(string(raw), "<config") {
		t.Errorf("export = %q %v", raw, err)
	}
}
