//go:build windows

package winevt

import (
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// platformProbe enumerates services and drivers through the service control
// manager and classifies Sysmon (stock or renamed). Read-only access only.
func platformProbe(hints []string) (SysmonInfo, error) {
	m, err := mgrConnectReadOnly()
	if err != nil {
		return SysmonInfo{}, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return SysmonInfo{}, err
	}
	var all []ServiceInfo
	for _, n := range names {
		s, err := openReadOnly(m, n)
		if err != nil {
			continue
		}
		cfg, cerr := s.Config()
		st, serr := s.Query()
		s.Close()
		if cerr != nil || serr != nil {
			continue
		}
		si := ServiceInfo{Name: n, DisplayName: cfg.DisplayName, Description: cfg.Description,
			BinaryPath: cfg.BinaryPathName, Driver: cfg.ServiceType&(windows.SERVICE_KERNEL_DRIVER|windows.SERVICE_FILE_SYSTEM_DRIVER) != 0,
			Running: st.State == svc.Running}
		all = append(all, si)
	}
	info := Classify(all, hints)
	if info.DriverName != "" {
		info.ConfigHash = readConfigHash(info.DriverName)
	}
	if info.ConfigHash == "" && info.ServiceName != "" {
		info.ConfigHash = readConfigHash(info.ServiceName)
	}
	return info, nil
}

func mgrConnectReadOnly() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

func openReadOnly(m *mgr.Mgr, name string) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

// readConfigHash reads the config hash Sysmon records under
// HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ConfigHash
// (best effort; the exact value format is [unverified] until a lab run).
func readConfigHash(name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name+`\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	if s, _, err := k.GetStringValue("ConfigHash"); err == nil {
		return normaliseHash(s)
	}
	if b, _, err := k.GetBinaryValue("ConfigHash"); err == nil {
		const hexd = "0123456789abcdef"
		out := make([]byte, 0, len(b)*2)
		for _, c := range b {
			out = append(out, hexd[c>>4], hexd[c&15])
		}
		return string(out)
	}
	return ""
}

// normaliseHash turns "SHA256=ABCD..." into lower-case "abcd...".
func normaliseHash(s string) string {
	if _, v, ok := strings.Cut(s, "="); ok {
		s = v
	}
	return strings.ToLower(strings.TrimSpace(s))
}
