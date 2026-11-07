// Package svcinstall installs the agent as a supervised service: a systemd
// unit on Linux and a Windows service (with restart-forever recovery) on
// Windows, plus the Windows service-control integration used by `agent run`.
// Service, binary and directory names are configurable and may be derived
// from a secret (design D-8, "obscurity is allowed").
package svcinstall

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Spec describes the service to install.
type Spec struct {
	// Name is the service (and, on Linux, unit) name, without ".service".
	Name        string
	DisplayName string
	Description string
	// Binary is the absolute path of the executable; Args follow it.
	Binary string
	Args   []string
	// Linux resource caps (design: MemoryMax, CPUQuota); empty = unset.
	MemoryMax string // e.g. "256M"
	CPUQuota  string // e.g. "50%"
	// WatchdogSec enables Type=notify with a systemd watchdog (0 = off).
	WatchdogSec int
}

func (s Spec) validate() error {
	if !validName(s.Name) {
		return errors.New("svcinstall: service name must be 1-64 chars of [A-Za-z0-9._-]")
	}
	if s.Binary == "" {
		return errors.New("svcinstall: binary path required")
	}
	return nil
}

func validName(n string) bool {
	if n == "" || len(n) > 64 || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "-") {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// Names are the per-event randomised identifiers.
type Names struct {
	Service string // service/unit name
	Binary  string // executable file name
	Dir     string // install directory name
}

var words = []string{"sys", "net", "udev", "dbus", "kern", "audit", "cron", "time", "mgr", "host", "log", "perf", "init", "core", "svc", "pkg"}

// DeriveNames derives stable, plausible-looking names from a secret (the
// vault's per-event value), so the controller can recompute them and
// detections can exclude the agent by path and hash instead of by name.
// This is obscurity, not a boundary.
func DeriveNames(secret []byte) Names {
	d := func(label string) string {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(label))
		sum := m.Sum(nil)
		return words[int(sum[0])%len(words)] + "-" + words[int(sum[1])%len(words)] + "d-" + hex.EncodeToString(sum[2:5])
	}
	return Names{Service: d("service"), Binary: d("binary"), Dir: d("dir")}
}

// stallChecks is how many consecutive stalled watchdog checks the Windows
// service handler tolerates before it exits non-zero, so SCM's restart-forever
// recovery replaces a wedged agent (the Windows half of the watchdog).
const stallChecks = 3

// stallCounter is the service handler's stall decision: exit after
// stallChecks consecutive stalled checks; a healthy check resets the count.
func stallCounter(stalled []string, n int) (exit bool, n2 int) {
	if len(stalled) == 0 {
		return false, 0
	}
	if n+1 >= stallChecks {
		return true, 0
	}
	return false, n + 1
}
