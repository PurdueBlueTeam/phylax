package svcinstall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

var unitTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
{{if .Watchdog}}Type=notify
NotifyAccess=main
WatchdogSec={{.Watchdog}}
{{else}}Type=simple
{{end}}ExecStart={{.ExecStart}}
Restart=always
RestartSec=1
OOMScoreAdjust=-900
{{if .MemoryMax}}MemoryMax={{.MemoryMax}}
{{end}}{{if .CPUQuota}}CPUQuota={{.CPUQuota}}
{{end}}UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
RestrictSUIDSGID=yes
# The agent needs full root, so there is no filesystem protection, no capability set and no
# namespace isolation here. Hardening only removes what it never uses.

[Install]
WantedBy=multi-user.target
`))

// SystemdUnit renders the unit file for s. Restart=always, RestartSec=1 and
// StartLimitIntervalSec=0 make systemd restart a killed agent forever; the
// remaining options are ones a root agent does not need.
func SystemdUnit(s Spec) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	desc := s.Description
	if desc == "" {
		desc = s.Name
	}
	parts := append([]string{s.Binary}, s.Args...)
	for i, p := range parts {
		parts[i] = systemdQuote(p)
	}
	var b bytes.Buffer
	err := unitTmpl.Execute(&b, map[string]any{
		"Description": strings.ReplaceAll(desc, "\n", " "), "ExecStart": strings.Join(parts, " "),
		"MemoryMax": s.MemoryMax, "CPUQuota": s.CPUQuota, "Watchdog": s.WatchdogSec,
	})
	return b.String(), err
}

// systemdQuote quotes one ExecStart word. systemd expands % and $ in
// ExecStart, so those are doubled.
func systemdQuote(a string) string {
	a = strings.NewReplacer("%", "%%", "$", "$$").Replace(a)
	if a == "" || strings.ContainsAny(a, " \t\"'\\;") {
		a = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a) + `"`
	}
	return a
}

// Systemd installs units into UnitDir and drives systemctl through Run.
type Systemd struct {
	UnitDir string         // default /etc/systemd/system
	Run     deadman.Runner // default deadman.ExecRunner
}

func (s *Systemd) dir() string {
	if s.UnitDir == "" {
		return "/etc/systemd/system"
	}
	return s.UnitDir
}

func (s *Systemd) run(ctx context.Context, args ...string) error {
	r := s.Run
	if r == nil {
		r = deadman.ExecRunner
	}
	_, err := r(ctx, "systemctl", args...)
	return err
}

// Install writes the unit atomically, reloads systemd, enables and starts it.
func (s *Systemd) Install(ctx context.Context, sp Spec) error {
	unit, err := SystemdUnit(sp)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return err
	}
	if err := atomicfile.WriteFile(filepath.Join(s.dir(), sp.Name+".service"), []byte(unit), 0o644); err != nil {
		return err
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", sp.Name + ".service"}, {"restart", sp.Name + ".service"}} {
		if err := s.run(ctx, a...); err != nil {
			return fmt.Errorf("systemctl %s: %w", a[0], err)
		}
	}
	return nil
}

// Uninstall stops and removes the unit.
func (s *Systemd) Uninstall(ctx context.Context, name string) error {
	if !validName(name) {
		return fmt.Errorf("svcinstall: bad service name %q", name)
	}
	_ = s.run(ctx, "disable", "--now", name+".service") // may already be gone
	if err := os.Remove(filepath.Join(s.dir(), name+".service")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.run(ctx, "daemon-reload")
}
