package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// ControllerCase is one controller module under test.
type ControllerCase struct {
	Module   module.ControllerModule
	Config   string        // YAML of modules/<name>.yml with the default settings
	Seed     []event.Event // fixture store contents for analysers (check 10)
	Commands []event.Event // the module's own command events, committed before it runs
	Now      time.Time
}

// Controller runs the controller-side conformance checks.
func Controller(t *testing.T, c ControllerCase) {
	t.Helper()
	errs := runControllerChecks(c)
	names := make([]string, 0, len(errs))
	for name := range errs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err := errs[name]
		t.Run(name, func(t *testing.T) {
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func runControllerChecks(c ControllerCase) map[string]error {
	checks := []struct {
		name string
		fn   func(ControllerCase) error
	}{
		{"no_config", checkControllerNoConfig},
		{"default_config", checkControllerDefaultConfig},
		{"stops_cleanly", checkControllerStopsCleanly},
		{"declared_kinds", checkControllerDeclaredKinds},
		{"config_decode", checkControllerConfigDecode},
		{"analysers", checkControllerAnalysers},
		{"tables_replay", checkControllerTablesReplay},
	}
	errs := make(map[string]error, len(checks))
	for _, ch := range checks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errs[ch.name] = fmt.Errorf("%s: panic: %v", c.Module.Manifest().Name, r)
				}
			}()
			errs[ch.name] = ch.fn(c)
		}()
	}
	return errs
}

// ctlHarness is a real controller on a temporary data dir and manifest.
type ctlHarness struct {
	c   *controller.Controller
	dir string
}

// newCtlHarness starts a real controller whose manifest holds one host and,
// when block is not empty, modules/<name>.yml. Seed events and command events
// are committed to the controller's own chain before any module runs.
func newCtlHarness(c ControllerCase, block string, seed, commands []event.Event) (*ctlHarness, error) {
	root, err := os.MkdirTemp("", "phylax-conformance-ctl-*")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ctlHarness, error) {
		os.RemoveAll(root)
		return nil, err
	}
	manDir := filepath.Join(root, "manifest")
	files := map[string]string{
		"topology.yml": `team: 3
controller: { host: ctl, agent_port: 7443, ui: "127.0.0.1:8443" }
segments:
  lan: { cidr: 10.0.0.0/24, nat: { public_pool: "172.25.23.0/24", mode: static_1to1_same_octet } }
`,
		"hosts.yml": `hosts:
  ctl: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
`,
	}
	if block != "" {
		files["modules/"+c.Module.Manifest().Name+".yml"] = block
	}
	for name, body := range files {
		p := filepath.Join(manDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			return fail(err)
		}
	}
	cfg := controller.Config{
		AgentListen:  "127.0.0.1:0",
		UIListen:     "off",
		DataDir:      filepath.Join(root, "data"),
		ManifestPath: manDir,
	}
	ctl, err := controller.New(context.Background(), cfg, controller.Options{})
	if err != nil {
		return fail(err)
	}
	h := &ctlHarness{c: ctl, dir: root}
	if err := h.commit(c.Module, seed); err != nil {
		h.close()
		return nil, err
	}
	if err := h.commit(c.Module, commands); err != nil {
		h.close()
		return nil, err
	}
	return h, nil
}

// commit stores events like the operator path does: a command kind must be
// one the module declares it emits.
func (h *ctlHarness) commit(m module.ControllerModule, evs []event.Event) error {
	emits := map[string]bool{}
	for _, t := range m.Manifest().Emits {
		emits[t.Kind] = true
	}
	for _, e := range evs {
		if len(emits) > 0 && !emits[e.Kind] {
			return fmt.Errorf("%s: committed kind %q is not in its manifest emits", m.Manifest().Name, e.Kind)
		}
		if _, err := h.c.EmitController(context.Background(), e); err != nil {
			return err
		}
	}
	return nil
}

func (h *ctlHarness) close() {
	h.c.Close()
	os.RemoveAll(h.dir)
}

// withEnabled makes sure the module block enables the module.
func withEnabled(cfg string) string {
	var m map[string]any
	_ = yaml.Unmarshal([]byte(cfg), &m)
	if _, ok := m["enabled"]; ok {
		return cfg
	}
	return cfg + "\nenabled: true\n"
}

type moduleRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func startModuleRun(c *controller.Controller, m module.ControllerModule) *moduleRun {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.RunModules(ctx, []module.ControllerModule{m})
	}()
	return &moduleRun{cancel: cancel, done: done}
}

func (r *moduleRun) stop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(6 * time.Second):
	}
}

// waitModule polls a controller module's health until ok reports true or d
// elapses.
func waitModule(c *controller.Controller, name string, d time.Duration, ok func(module.Health) bool) (module.Health, bool) {
	deadline := time.Now().Add(d)
	for {
		hl := c.ModuleHealth()[name]
		if ok(hl) {
			return hl, true
		}
		if time.Now().After(deadline) {
			return hl, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkControllerNoConfig is the no-block check: the module ends unavailable
// or disabled, never running.
func checkControllerNoConfig(c ControllerCase) error {
	name := c.Module.Manifest().Name
	h, err := newCtlHarness(c, "", nil, nil)
	if err != nil {
		return err
	}
	defer h.close()
	run := startModuleRun(h.c, c.Module)
	defer run.stop()
	hl, ok := waitModule(h.c, name, 10*time.Second, func(hl module.Health) bool {
		return hl.State == module.StateUnavailable || hl.State == module.StateDisabled
	})
	if !ok {
		return fmt.Errorf("%s: without a config block it ends %q, not unavailable or disabled", name, hl.State)
	}
	return nil
}

// checkControllerDefaultConfig is the default-block check: health reaches ok
// or unavailable within 10 s.
func checkControllerDefaultConfig(c ControllerCase) error {
	name := c.Module.Manifest().Name
	h, err := newCtlHarness(c, withEnabled(c.Config), nil, nil)
	if err != nil {
		return err
	}
	defer h.close()
	run := startModuleRun(h.c, c.Module)
	defer run.stop()
	if hl, ok := waitModule(h.c, name, 10*time.Second, func(hl module.Health) bool {
		return hl.State == module.StateOK || hl.State == module.StateUnavailable
	}); !ok {
		return fmt.Errorf("%s: health did not reach ok or unavailable within 10s: %+v", name, hl)
	}
	return nil
}

// checkControllerStopsCleanly: after cancel the runner returns within 5 s and
// leaves no goroutine behind.
func checkControllerStopsCleanly(c ControllerCase) error {
	name := c.Module.Manifest().Name
	h, err := newCtlHarness(c, withEnabled(c.Config), nil, nil)
	if err != nil {
		return err
	}
	defer h.close()
	before := goroutineKeys()
	run := startModuleRun(h.c, c.Module)
	waitModule(h.c, name, 5*time.Second, func(hl module.Health) bool { return hl.State != "" })
	time.Sleep(agentSettle)
	run.cancel()
	select {
	case <-run.done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%s: the module runner did not return within 5s of cancel", name)
	}
	deadline := time.Now().Add(time.Second)
	for {
		extra := extraGoroutines(before, goroutineKeys())
		if len(extra) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: goroutines still running after stop: %v", name, extra)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkControllerDeclaredKinds: every stored event of agent "controller" that
// carries the module's prefix validates and is one the manifest declares.
func checkControllerDeclaredKinds(c ControllerCase) error {
	name := c.Module.Manifest().Name
	h, err := newCtlHarness(c, withEnabled(c.Config), c.Seed, c.Commands)
	if err != nil {
		return err
	}
	defer h.close()
	run := startModuleRun(h.c, c.Module)
	defer run.stop()
	waitModule(h.c, name, 5*time.Second, func(hl module.Health) bool { return hl.State != "" })
	time.Sleep(agentSettle)
	evs, err := h.c.Store().Events(context.Background(), store.Query{Agent: controller.ControllerAgent, Limit: store.MaxQueryLimit})
	if err != nil {
		return err
	}
	emits := map[string]bool{}
	for _, t := range c.Module.Manifest().Emits {
		emits[t.Kind] = true
	}
	for _, e := range evs {
		if !strings.HasPrefix(e.Kind, name+".") {
			continue
		}
		if err := event.Validate(e); err != nil {
			return fmt.Errorf("%s: stored %s does not validate: %v", name, e.Kind, err)
		}
		if !emits[e.Kind] {
			return fmt.Errorf("%s: stored %s, which its manifest does not declare", name, e.Kind)
		}
	}
	return nil
}

// checkControllerConfigDecode: a Configurable module's block decodes the
// generic fields strictly, and a module handed an unknown key fails closed.
func checkControllerConfigDecode(c ControllerCase) error {
	cfg, ok := c.Module.(module.Configurable)
	if !ok {
		return nil
	}
	name := c.Module.Manifest().Name
	block := cfg.ConfigBlock()
	if block == nil {
		return fmt.Errorf("%s: ConfigBlock returns nil", name)
	}
	t := reflect.TypeOf(block)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("%s: ConfigBlock %T is not a struct", name, block)
	}
	v := reflect.New(t)
	if err := decodeStrict(v.Interface(), `{"enabled":true,"act_enabled":true}`); err != nil {
		return fmt.Errorf("%s: block rejects the generic fields: %v", name, err)
	}
	el := v.Elem()
	enabled, act := el.FieldByName("Enabled"), el.FieldByName("ActEnabled")
	if !enabled.IsValid() || !act.IsValid() || enabled.Kind() != reflect.Bool || act.Kind() != reflect.Bool {
		return fmt.Errorf("%s: block %s carries no enabled and act_enabled fields", name, t)
	}
	if !enabled.Bool() || !act.Bool() {
		return fmt.Errorf("%s: block did not read enabled and act_enabled", name)
	}
	if err := decodeStrict(reflect.New(t).Interface(), `{"x_unknown":1}`); err == nil {
		return fmt.Errorf("%s: block accepts an unknown field", name)
	}

	// Fail closed on a bad block: never ok.
	h, err := newCtlHarness(c, withEnabled(c.Config)+"x_unknown: 1\n", nil, nil)
	if err != nil {
		return err
	}
	defer h.close()
	run := startModuleRun(h.c, c.Module)
	defer run.stop()
	hl, _ := waitModule(h.c, name, 10*time.Second, func(hl module.Health) bool {
		return hl.State == module.StateUnavailable || hl.State == module.StateError || hl.State == module.StateRestarting
	})
	if hl.State == module.StateOK || hl.State == "" {
		return fmt.Errorf("%s: accepts an unknown config key (health %q)", name, hl.State)
	}
	return nil
}

// checkControllerAnalysers: each analyser run twice over the same store and
// clock returns byte-identical JSON.
func checkControllerAnalysers(c ControllerCase) error {
	ap, ok := c.Module.(module.AnalyzerProvider)
	if !ok || len(ap.Analyzers()) == 0 {
		return nil
	}
	name := c.Module.Manifest().Name
	h, err := newCtlHarness(c, withEnabled(c.Config), c.Seed, nil)
	if err != nil {
		return err
	}
	defer h.close()
	for _, a := range ap.Analyzers() {
		var first, second []byte
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			evs, err := a.Run(ctx, h.c.Store(), c.Now)
			cancel()
			if err != nil {
				return fmt.Errorf("%s: analyser %s: %v", name, a.Name, err)
			}
			raw, err := json.Marshal(evs)
			if err != nil {
				return fmt.Errorf("%s: analyser %s: %v", name, a.Name, err)
			}
			if i == 0 {
				first = raw
			} else {
				second = raw
			}
		}
		if string(first) != string(second) {
			return fmt.Errorf("%s: analyser %s is not deterministic:\n%s\n%s", name, a.Name, first, second)
		}
	}
	return nil
}

// tableDump is one table's rows, sorted by their encoded cells.
type tableDump struct {
	cols []string
	rows [][]string
}

// checkControllerTablesReplay is check 10, R10: a module's tables are a
// projection of its own events, so they rebuild identically from them.
func checkControllerTablesReplay(c ControllerCase) error {
	name := c.Module.Manifest().Name
	tables := c.Module.Manifest().Tables
	if len(tables) == 0 {
		return nil
	}
	h, err := newCtlHarness(c, withEnabled(c.Config), c.Seed, c.Commands)
	if err != nil {
		return err
	}
	defer h.close()
	db := h.c.Store().ModuleDB(name)
	// First run (the operator's) fills the tables.
	run := startModuleRun(h.c, c.Module)
	if _, ok := waitModule(h.c, name, 10*time.Second, func(hl module.Health) bool {
		return hl.State == module.StateOK || hl.State == module.StateUnavailable
	}); !ok {
		run.stop()
		return fmt.Errorf("%s: module did not become ready for the table check", name)
	}
	first, err := waitStableDump(db, tables)
	run.stop()
	if err != nil {
		return err
	}
	if len(c.Seed)+len(c.Commands) > 0 {
		rows := 0
		for _, t := range tables {
			rows += len(first[t].rows)
		}
		if rows == 0 {
			return fmt.Errorf("%s: its tables are empty after %d seeded events; the writer did not project them", name, len(c.Seed)+len(c.Commands))
		}
	}
	// Keep the schema, drop the contents and let a second run rebuild them
	// from the committed events.
	ddl := make(map[string]string, len(tables))
	for _, t := range tables {
		if ddl[t], err = tableDDL(db, t); err != nil {
			return err
		}
		if _, err := db.Exec(context.Background(), "DROP TABLE "+t); err != nil {
			return fmt.Errorf("%s: drop %s: %w", name, t, err)
		}
		if _, err := db.Exec(context.Background(), ddl[t]); err != nil {
			return fmt.Errorf("%s: recreate %s: %w", name, t, err)
		}
	}
	run2 := startModuleRun(h.c, c.Module)
	defer run2.stop()
	deadline := time.Now().Add(5 * time.Second)
	var second map[string]tableDump
	for {
		second, err = dumpTables(db, tables)
		if err != nil {
			return err
		}
		if dumpsEqual(first, second) || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return diffDumps(name, tables, first, second)
}

// waitStableDump dumps the tables until two consecutive dumps agree.
func waitStableDump(db store.ModuleDB, tables []string) (map[string]tableDump, error) {
	deadline := time.Now().Add(5 * time.Second)
	prev, err := dumpTables(db, tables)
	if err != nil {
		return nil, err
	}
	for {
		time.Sleep(50 * time.Millisecond)
		cur, err := dumpTables(db, tables)
		if err != nil {
			return nil, err
		}
		if dumpsEqual(prev, cur) || time.Now().After(deadline) {
			return cur, nil
		}
		prev = cur
	}
}

func tableDDL(db store.ModuleDB, table string) (string, error) {
	rows, err := db.Query(context.Background(), "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", table)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", fmt.Errorf("table %s was never created", table)
	}
	var ddl string
	if err := rows.Scan(&ddl); err != nil {
		return "", err
	}
	return ddl, nil
}

func dumpTables(db store.ModuleDB, tables []string) (map[string]tableDump, error) {
	out := make(map[string]tableDump, len(tables))
	for _, t := range tables {
		rows, err := db.Query(context.Background(), "SELECT * FROM "+t)
		if err != nil {
			return nil, err
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return nil, err
		}
		var got [][]string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			row := make([]string, len(cols))
			for i, v := range vals {
				row[i] = cellText(v)
			}
			got = append(got, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		sort.Slice(got, func(i, j int) bool { return strings.Join(got[i], "\x00") < strings.Join(got[j], "\x00") })
		out[t] = tableDump{cols: cols, rows: got}
	}
	return out, nil
}

func cellText(v any) string {
	switch x := v.(type) {
	case nil:
		return "\x00NULL"
	case []byte:
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(x)
	}
}

func dumpsEqual(a, b map[string]tableDump) bool {
	if len(a) != len(b) {
		return false
	}
	for t, d := range a {
		o, ok := b[t]
		if !ok || !reflect.DeepEqual(d, o) {
			return false
		}
	}
	return true
}

// diffDumps names the table and column a rebuild could not reproduce.
func diffDumps(name string, tables []string, first, second map[string]tableDump) error {
	for _, t := range tables {
		a, b := first[t], second[t]
		if reflect.DeepEqual(a, b) {
			continue
		}
		for i := 0; i < len(a.cols) && i < len(b.cols); i++ {
			if a.cols[i] != b.cols[i] {
				return fmt.Errorf("%s: table %s: column %d is %q after replay, %q originally", name, t, i, b.cols[i], a.cols[i])
			}
			if !sameValues(column(a, i), column(b, i)) {
				return fmt.Errorf("%s: table %s: column %s holds data no event carries", name, t, a.cols[i])
			}
		}
		col := "row"
		if len(a.cols) > 0 {
			col = a.cols[0]
		}
		return fmt.Errorf("%s: table %s: column %s differs after replay (%d rows, was %d)", name, t, col, len(b.rows), len(a.rows))
	}
	return nil
}

func column(d tableDump, i int) []string {
	out := make([]string, 0, len(d.rows))
	for _, r := range d.rows {
		if i < len(r) {
			out = append(out, r[i])
		}
	}
	sort.Strings(out)
	return out
}

func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
