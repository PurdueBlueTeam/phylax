package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/firewall"
)

// This file holds the seams the Windows, Active Directory, network-device and
// Splunk actions use. Each backend is an interface so the actions (checks,
// plans, refusals, rollback data) are unit tested on Linux against fakes; the
// real implementations live in *_windows.go files (registry, SCM, ADSI, event
// log, audit policy, COM firewall) or in portable code (exec, Splunk REST).

// WinEnv groups the backends. A nil member makes the actions that need it fail
// with ErrUnsupported; nothing falls back to touching the host another way.
type WinEnv struct {
	Reg      RegistryStore
	Svc      ServiceConfigurer
	Audit    AuditPolicy
	Exec     Executor
	Events   EventLog
	Defender DefenderBackend
	// Firewall opens the Windows Firewall backend (COM on Windows).
	Firewall func() (firewall.WinBackend, error)
	AD       ADBackend
	Devices  DeviceDirectory
	Splunk   SplunkDirectory
	// DepotDir holds cached installers (MSUs) the agent may install from.
	DepotDir string
}

var extraHandlers = map[string]func(ctx context.Context, env *Env, e deadman.Entry) error{}

// RegisterUndo registers the dead-man handler for a rollback kind; the data is
// decoded by the handler itself. Called from init functions.
func RegisterUndo(kind string, fn func(ctx context.Context, env *Env, e deadman.Entry) error) {
	if _, dup := extraHandlers[kind]; dup {
		panic("actions: duplicate undo kind " + kind)
	}
	extraHandlers[kind] = fn
}

func Unsupported(what string) error { return fmt.Errorf("%s: %w", what, ErrUnsupported) }

// ---- registry ----

// RegValue is a registry value in a platform-neutral, JSON-able form.
type RegValue struct {
	Type  string   `json:"type"` // dword qword sz expand_sz multi_sz binary
	Str   string   `json:"str,omitempty"`
	Num   uint64   `json:"num,omitempty"`
	Multi []string `json:"multi,omitempty"`
	Bin   []byte   `json:"bin,omitempty"`
}

// RegistryStore reads and writes HKLM values. Keys are written
// `HKLM\SOFTWARE\...` (see normRegKey).
type RegistryStore interface {
	Get(ctx context.Context, key, name string) (RegValue, bool, error)
	Set(ctx context.Context, key, name string, v RegValue) error
	// Delete removes a value; a missing value is not an error.
	Delete(ctx context.Context, key, name string) error
	// ValueNames lists the value names of a key (missing key: none).
	ValueNames(ctx context.Context, key string) ([]string, error)
}

// ---- services ----

// SvcConfig is a service's configuration as far as the actions care.
type SvcConfig struct {
	Exists  bool   `json:"exists"`
	Start   string `json:"start"` // auto | auto_delayed | manual | disabled
	Binary  string `json:"binary,omitempty"`
	Account string `json:"account,omitempty"`
	Running bool   `json:"running"`
}

// ServiceConfigurer reads and changes a service's start type (the plain
// ServiceManager cannot express manual or delayed start).
type ServiceConfigurer interface {
	Config(ctx context.Context, unit string) (SvcConfig, error)
	SetStart(ctx context.Context, unit, start string) error
}

// ---- audit policy ----

// AuditSetting is one audit subcategory's setting.
type AuditSetting struct {
	Success bool `json:"success"`
	Failure bool `json:"failure"`
}

func (a AuditSetting) String() string {
	switch {
	case a.Success && a.Failure:
		return "success,failure"
	case a.Success:
		return "success"
	case a.Failure:
		return "failure"
	}
	return "none"
}

// AuditPolicy reads and sets advanced audit policy by subcategory name.
type AuditPolicy interface {
	Get(ctx context.Context, subcategory string) (AuditSetting, error)
	Set(ctx context.Context, subcategory string, s AuditSetting) error
}

// ---- exec ----

// Executor runs an allowlisted program (the explicit host.exec escape hatch;
// only auditpol, powershell for Defender and wusa go through it).
type Executor interface {
	Run(ctx context.Context, prog string, args ...string) (stdout string, exit int, err error)
}

// ---- event log ----

// EventCount is the result of an event-log count.
type EventCount struct {
	N      int
	Latest time.Time
}

// EventLog counts events (System channel for Netlogon 5827-5831).
type EventLog interface {
	Count(ctx context.Context, channel string, ids []int, since time.Time) (EventCount, error)
}

// ---- defender ----

// Exclusion kinds.
const (
	ExclPath      = "path"
	ExclExtension = "extension"
	ExclProcess   = "process"
)

// Exclusion is one Defender exclusion.
type Exclusion struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// DefenderBackend lists and edits Defender exclusions and real-time protection.
type DefenderBackend interface {
	Exclusions(ctx context.Context) ([]Exclusion, error)
	AddExclusion(ctx context.Context, e Exclusion) error
	RemoveExclusion(ctx context.Context, e Exclusion) error
	RealtimeEnabled(ctx context.Context) (bool, error)
	SetRealtime(ctx context.Context, enabled bool) error
}

// ---- registry key helpers ----

// normRegKey canonicalises "HKLM\\..." / "HKEY_LOCAL_MACHINE\\..." / "HKLM:\\..."
// to `HKLM\...` with single backslashes; only HKLM is accepted.
func normRegKey(k string) (string, error) {
	k = strings.ReplaceAll(k, "/", `\`)
	for strings.Contains(k, `\\`) {
		k = strings.ReplaceAll(k, `\\`, `\`)
	}
	k = strings.TrimSuffix(strings.TrimPrefix(k, `\`), `\`)
	hive, rest, _ := strings.Cut(k, `\`)
	switch strings.ToUpper(strings.TrimSuffix(hive, ":")) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
	default:
		return "", errors.New("only HKLM keys are allowed")
	}
	if rest == "" || strings.Contains(rest, "..") || strings.ContainsRune(rest, 0) || len(rest) > 512 {
		return "", errors.New("invalid registry key")
	}
	return `HKLM\` + rest, nil
}

// regPath is a case-insensitive comparison key for registry key + value name.
func regPath(key, name string) string { return strings.ToLower(key + `\` + name) }

func jsonUndo(e deadman.Entry, v any) error { return json.Unmarshal(e.Data, v) }
