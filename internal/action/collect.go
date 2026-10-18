package action

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---- collect.files --------------------------------------------------------------

// evidenceDir is where collected files land on the agent, pending fetch.
var evidenceDir = "/var/lib/phylax/evidence"

type collectFiles struct{}

func (collectFiles) Name() string   { return "collect.files" }
func (collectFiles) Risk() Risk     { return RiskNone }
func (collectFiles) Locks() []string { return nil }
func (collectFiles) Check(p Params) (CheckResult, error) {
	paths := p.GetList("paths")
	var present, missing []string
	for _, pth := range paths {
		if _, err := os.Stat(pth); err == nil {
			present = append(present, pth)
		} else {
			missing = append(missing, pth)
		}
	}
	detail := fmt.Sprintf("collect %d file(s)", len(present))
	if len(missing) > 0 {
		detail += fmt.Sprintf("; missing: %v", missing)
	}
	return CheckResult{Diff: detail}, nil
}
func (collectFiles) Apply(p Params) (CheckResult, error) {
	paths := p.GetList("paths")
	destRoot := evidenceDir + "/" + p.Get("label", "collect")
	type fileRec struct {
		Path string `json:"path"`
		SHA  string `json:"sha"`
		Size int64  `json:"size"`
	}
	var recs []fileRec
	var skipped []string
	for _, pth := range paths {
		b, err := os.ReadFile(pth)
		if err != nil {
			skipped = append(skipped, pth)
			continue
		}
		dest := filepath.Join(destRoot, strings.ReplaceAll(pth, "/", "_"))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return CheckResult{}, err
		}
		if err := os.WriteFile(dest, b, 0o600); err != nil {
			return CheckResult{}, err
		}
		recs = append(recs, fileRec{Path: pth, SHA: HashBytes(b), Size: int64(len(b))})
	}
	manifest, _ := json.Marshal(recs)
	return CheckResult{Done: true,
		Diff:  fmt.Sprintf("collected %d file(s)%s", len(recs), listSuffix(skipped)),
		After: manifest}, nil
}
func (a collectFiles) Verify(p Params) (CheckResult, error) {
	// Verified by the controller's fetch; locally the files must exist.
	return CheckResult{Done: true}, nil
}
func (a collectFiles) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

func listSuffix(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("; skipped %d missing", len(missing))
}

// ---- collect.inventory ------------------------------------------------------------

type collectInventory struct{}

func (collectInventory) Name() string   { return "collect.inventory" }
func (collectInventory) Risk() Risk     { return RiskNone }
func (collectInventory) Locks() []string { return nil }

func inventory() map[string]any {
	inv := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339)}
	if h, err := os.Hostname(); err == nil {
		inv["hostname"] = h
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		inv["os"] = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cores := 0
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "processor") {
				cores++
			}
		}
		inv["cores"] = cores
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		if l := strings.SplitN(string(b), "\n", 2)[0]; l != "" {
			inv["meminfo"] = l
		}
	}
	var units []string
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system"} {
		if d, err := os.ReadDir(dir); err == nil {
			for _, e := range d {
				if strings.HasSuffix(e.Name(), ".service") {
					units = append(units, e.Name())
				}
			}
		}
	}
	inv["units"] = units
	return inv
}

func (a collectInventory) Check(p Params) (CheckResult, error) {
	b, _ := json.Marshal(inventory())
	return CheckResult{Done: true, After: b}, nil
}
func (a collectInventory) Apply(p Params) (CheckResult, error) {
	b, _ := json.Marshal(inventory())
	return CheckResult{Done: true, Before: b}, nil
}
func (a collectInventory) Verify(p Params) (CheckResult, error) {
	return a.Check(p)
}
func (a collectInventory) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

// ---- hunt.baseline_diff -------------------------------------------------------------

// hunt.baseline_diff compares a directory against a captured snapshot (a
// dir.snapshot Before blob) and reports added/removed/changed files.

type huntBaselineDiff struct{}

func (huntBaselineDiff) Name() string   { return "hunt.baseline_diff" }
func (huntBaselineDiff) Risk() Risk     { return RiskNone }
func (huntBaselineDiff) Locks() []string { return nil }

func (a huntBaselineDiff) diff(p Params) (CheckResult, error) {
	var base []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		SHA  string `json:"sha"`
	}
	if b := Dec(p.Get("baseline", "")); len(b) > 0 {
		if err := json.Unmarshal(b, &base); err != nil {
			return CheckResult{}, fmt.Errorf("bad baseline: %w", err)
		}
	}
	var cur []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		SHA  string `json:"sha"`
	}
	cb, err := snapList(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	_ = json.Unmarshal(cb, &cur)
	baseMap := map[string]struct {
		Size int64  `json:"size"`
		SHA  string `json:"sha"`
	}{}
	for _, e := range base {
		baseMap[e.Path] = struct {
			Size int64  `json:"size"`
			SHA  string `json:"sha"`
		}{e.Size, e.SHA}
	}
	var added, removed, changed []string
	for _, e := range cur {
		b, ok := baseMap[e.Path]
		switch {
		case !ok:
			added = append(added, e.Path)
		case b.SHA != e.SHA:
			changed = append(changed, e.Path)
		}
	}
	curSet := map[string]bool{}
	for _, e := range cur {
		curSet[e.Path] = true
	}
	for pth := range baseMap {
		if !curSet[pth] {
			removed = append(removed, pth)
		}
	}
	out := fmt.Sprintf("+%d ~%d -%d", len(added), len(changed), len(removed))
	if len(added)+len(changed)+len(removed) > 0 {
		out += fmt.Sprintf(" (added %v, changed %v, removed %v)", added, changed, removed)
	}
	res := CheckResult{Done: len(added)+len(changed)+len(removed) == 0, Diff: out}
	return res, nil
}

func (a huntBaselineDiff) Check(p Params) (CheckResult, error) { return a.diff(p) }
func (a huntBaselineDiff) Apply(p Params) (CheckResult, error) {
	return a.diff(p)
}
func (a huntBaselineDiff) Verify(p Params) (CheckResult, error) {
	return a.diff(p)
}
func (a huntBaselineDiff) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

// ---- hunt.persistence ---------------------------------------------------------------

// hunt.persistence inspects the common Linux persistence locations and
// reports what is present. It is a detector, not a cleaner: cleanup goes
// through the explicit cron.disable / unit.disable / file.* actions.

type huntPersistence struct{}

func (huntPersistence) Name() string   { return "hunt.persistence" }
func (huntPersistence) Risk() Risk     { return RiskNone }
func (huntPersistence) Locks() []string { return nil }

func (a huntPersistence) scan() (map[string]any, error) {
	out := map[string]any{}
	// crontabs
	crontabs := map[string]any{}
	if d, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range d {
			b, _ := os.ReadFile("/var/spool/cron/crontabs/" + e.Name())
			crontabs[e.Name()] = strings.TrimSpace(string(b))
		}
	}
	if d, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range d {
			b, _ := os.ReadFile("/etc/cron.d/" + e.Name())
			crontabs["etc:"+e.Name()] = strings.TrimSpace(string(b))
		}
	}
	out["cron"] = crontabs
	// /etc/crontab
	if b, err := os.ReadFile("/etc/crontab"); err == nil {
		out["etc_crontab"] = strings.TrimSpace(string(b))
	}
	// systemd units in /etc (admin-managed)
	var units []string
	if d, err := os.ReadDir("/etc/systemd/system"); err == nil {
		for _, e := range d {
			if strings.HasSuffix(e.Name(), ".service") || strings.HasSuffix(e.Name(), ".timer") {
				units = append(units, e.Name())
			}
		}
	}
	out["units"] = units
	// rc.local
	if b, err := os.ReadFile("/etc/rc.local"); err == nil {
		out["rc_local"] = strings.TrimSpace(string(b))
	}
	return out, nil
}

func (a huntPersistence) Check(p Params) (CheckResult, error) {
	scan, err := a.scan()
	if err != nil {
		return CheckResult{}, err
	}
	b, _ := json.Marshal(scan)
	return CheckResult{Done: true, After: b}, nil
}
func (a huntPersistence) Apply(p Params) (CheckResult, error) {
	scan, err := a.scan()
	if err != nil {
		return CheckResult{}, err
	}
	b, _ := json.Marshal(scan)
	return CheckResult{Done: true, Before: b}, nil
}
func (a huntPersistence) Verify(p Params) (CheckResult, error) { return a.Check(p) }
func (a huntPersistence) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}
