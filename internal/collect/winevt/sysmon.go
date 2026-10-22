package winevt

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// SysmonConfigXML is the embedded Phylax Sysmon configuration: a Balanced-style
// profile in the structure of sysmon-modular (MIT, Olaf Hartong,
// https://github.com/olafhartong/sysmon-modular) with the CCDC includes from
// the design. It is pinned to Sysmon schema 4.90 (Sysmon 15.x).
//
//go:embed sysmon_config.xml
var SysmonConfigXML []byte

// SysmonConfigSchema is the schemaversion the embedded config targets.
const SysmonConfigSchema = "4.90"

// SysmonConfigSHA256 returns the hex sha256 of the embedded config, comparable
// with the config hash Sysmon reports and the heartbeat's Sysmon block.
func SysmonConfigSHA256() string {
	h := sha256.Sum256(SysmonConfigXML)
	return hex.EncodeToString(h[:])
}

// ServiceInfo is what the Windows probe learns about one installed service or
// kernel driver; Classify is pure so it can be tested off Windows.
type ServiceInfo struct {
	Name        string
	DisplayName string
	Description string
	BinaryPath  string
	Product     string // ProductName from the binary's version resource, if read
	Driver      bool   // kernel/filesystem driver rather than a Win32 service
	Running     bool
}

// SysmonInfo describes the local Sysmon installation.
type SysmonInfo struct {
	Present       bool   `json:"present"`
	Running       bool   `json:"running"`
	ServiceName   string `json:"service_name,omitempty"`
	DriverName    string `json:"driver_name,omitempty"`
	DriverRunning bool   `json:"driver_running"`
	BinaryPath    string `json:"binary_path,omitempty"`
	ConfigHash    string `json:"config_hash,omitempty"`
	Renamed       bool   `json:"renamed"` // service or driver is not under a stock name
}

// Healthy means both the service and the driver are running.
func (i SysmonInfo) Healthy() bool { return i.Present && i.Running && i.DriverRunning }

var stockServiceNames = []string{"sysmon", "sysmon64"}
var stockDriverNames = []string{"sysmondrv"}

func lowerIn(s string, set []string) bool {
	s = strings.ToLower(s)
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// Classify finds Sysmon's service and driver among services. Renamed
// installs (design D-8: "sysmon -d", renamed binary) are recognised by, in
// order: an exact name in hints (the names the agent installed under),
// stock names, the version resource ProductName, the service/driver
// description Sysmon registers, and the image file name.
func Classify(services []ServiceInfo, hints []string) SysmonInfo {
	var info SysmonInfo
	isHint := func(n string) bool { return lowerIn(n, lowerAll(hints)) }
	for _, s := range services {
		base := strings.ToLower(baseName(s.BinaryPath))
		prodSysmon := strings.Contains(strings.ToLower(s.Product), "sysmon") ||
			strings.Contains(strings.ToLower(s.Product), "system monitor")
		if s.Driver {
			match := isHint(s.Name) || lowerIn(s.Name, stockDriverNames) || prodSysmon ||
				strings.Contains(strings.ToLower(s.Description), "system monitor driver") ||
				base == "sysmondrv.sys"
			if match && info.DriverName == "" {
				info.DriverName, info.DriverRunning = s.Name, s.Running
			}
			continue
		}
		match := isHint(s.Name) || lowerIn(s.Name, stockServiceNames) || prodSysmon ||
			strings.EqualFold(strings.TrimSpace(s.Description), "System Monitor service") ||
			base == "sysmon.exe" || base == "sysmon64.exe"
		if match && info.ServiceName == "" {
			info.Present, info.ServiceName, info.Running, info.BinaryPath = true, s.Name, s.Running, s.BinaryPath
		}
	}
	info.Renamed = info.Present && (!lowerIn(info.ServiceName, stockServiceNames) ||
		(info.DriverName != "" && !lowerIn(info.DriverName, stockDriverNames)))
	return info
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}
