package winevt

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestClassifyStock(t *testing.T) {
	info := Classify([]ServiceInfo{
		{Name: "Spooler", BinaryPath: `C:\Windows\System32\spoolsv.exe`, Running: true},
		{Name: "Sysmon64", Description: "System Monitor service", BinaryPath: `C:\Windows\Sysmon64.exe`, Running: true},
		{Name: "SysmonDrv", Driver: true, BinaryPath: `C:\Windows\SysmonDrv.sys`, Running: true},
	}, nil)
	if !info.Present || !info.Running || !info.DriverRunning || info.ServiceName != "Sysmon64" || info.DriverName != "SysmonDrv" || info.Renamed || !info.Healthy() {
		t.Fatalf("%+v", info)
	}
}

func TestClassifyRenamedByHints(t *testing.T) {
	svcs := []ServiceInfo{
		{Name: "WinSvcHelper", BinaryPath: `C:\Windows\WinSvcHelper.exe`, Running: true},
		{Name: "WinSvcDrv", Driver: true, BinaryPath: `C:\Windows\System32\drivers\WinSvcDrv.sys`, Running: true},
		{Name: "Other", Running: true},
	}
	if info := Classify(svcs, nil); info.Present {
		t.Fatal("must not guess without any signal")
	}
	info := Classify(svcs, []string{"winsvchelper", "WINSVCDRV"})
	if !info.Present || info.ServiceName != "WinSvcHelper" || info.DriverName != "WinSvcDrv" || !info.Renamed {
		t.Fatalf("%+v", info)
	}
}

func TestClassifyRenamedByProductAndDescription(t *testing.T) {
	info := Classify([]ServiceInfo{
		{Name: "svcA", Product: "Sysinternals Sysmon", BinaryPath: `C:\Windows\a.exe`, Running: true},
		{Name: "drvB", Driver: true, Description: "System Monitor driver", Running: false},
	}, nil)
	if !info.Present || info.ServiceName != "svcA" || info.DriverName != "drvB" || info.DriverRunning || info.Healthy() || !info.Renamed {
		t.Fatalf("%+v", info)
	}
	info = Classify([]ServiceInfo{{Name: "x", Description: " System Monitor service ", Running: false}}, nil)
	if !info.Present || info.Running {
		t.Fatalf("%+v", info)
	}
}

func TestClassifyAbsent(t *testing.T) {
	if info := Classify([]ServiceInfo{{Name: "wuauserv"}, {Name: "ntfs", Driver: true}}, nil); info.Present || info.Renamed {
		t.Fatalf("%+v", info)
	}
	if info := Classify(nil, nil); info.Present {
		t.Fatal("empty")
	}
}

func TestEmbeddedConfigWellFormed(t *testing.T) {
	var doc struct {
		XMLName xml.Name `xml:"Sysmon"`
		Schema  string   `xml:"schemaversion,attr"`
		Hash    string   `xml:"HashAlgorithms"`
		Groups  []struct {
			Name string `xml:"name,attr"`
		} `xml:"EventFiltering>RuleGroup"`
	}
	if err := xml.Unmarshal(SysmonConfigXML, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != SysmonConfigSchema || !strings.Contains(doc.Hash, "sha256") {
		t.Fatalf("%+v", doc)
	}
	have := map[string]bool{}
	for _, g := range doc.Groups {
		have[g.Name] = true
	}
	// Every Sysmon event the module consumes must have a rule group.
	for _, g := range []string{"ProcessCreate", "NetworkConnect", "ProcessTerminate", "DriverLoad", "ImageLoad", "CreateRemoteThread",
		"ProcessAccess", "FileCreate", "RegistryEvent", "PipeEvent", "WmiEvent", "DnsQuery", "FileDelete", "ProcessTampering"} {
		if !have[g] {
			t.Errorf("config lacks %s", g)
		}
	}
	s := string(SysmonConfigXML)
	if !strings.Contains(s, "sysmon-modular") || !strings.Contains(s, "lsass.exe") {
		t.Error("attribution or CCDC LSASS include missing")
	}
	if len(SysmonConfigSHA256()) != 64 {
		t.Fatal("hash")
	}
}
