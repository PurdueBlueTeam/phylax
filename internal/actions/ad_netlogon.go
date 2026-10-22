package actions

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Domain-controller hardening that is registry-backed: Zerologon
// (CVE-2020-1472) enforcement and checks, the RPC dynamic port range, SMBv1.
// Rules from the design: Zerologon first on DCs; no NTLM changes; patch level
// is reported, never assumed.

const (
	netlogonParams = `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
	ntCurrentVer   = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	productOptions = `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`
	rpcInternetKey = `HKLM\SOFTWARE\Microsoft\Rpc\Internet`
)

// zerologonMinUBR is the first update revision per Windows build that contains
// the August 2020 Netlogon fix. Builds at or above 20348 (Server 2022) shipped
// with it. Builds not listed (2012 R2 and older) cannot be judged by build
// number alone and are reported "unknown".
var zerologonMinUBR = map[int]int{
	14393: 3930, // Server 2016, KB4571694
	17763: 1397, // Server 2019, KB4565349
	18363: 1016, // 1909, KB4565351
	19041: 450,  // 2004/20H2, KB4566782
}

// zerologonPatched reports "yes", "no" or "unknown" for a build.
func zerologonPatched(build, ubr int) string {
	if build >= 20348 {
		return "yes"
	}
	min, ok := zerologonMinUBR[build]
	if !ok {
		return "unknown"
	}
	if ubr >= min {
		return "yes"
	}
	return "no"
}

type osInfo struct {
	Build   int
	UBR     int
	Product string // ProductType: LanmanNT (DC), ServerNT, WinNT
}

func readOSInfo(ctx context.Context, rs RegistryStore) (osInfo, error) {
	var oi osInfo
	b, _, err := regString(ctx, rs, ntCurrentVer, "CurrentBuildNumber")
	if err != nil {
		return oi, err
	}
	oi.Build, _ = strconv.Atoi(strings.TrimSpace(b))
	u, _, err := regUint(ctx, rs, ntCurrentVer, "UBR")
	if err != nil {
		return oi, err
	}
	oi.UBR = int(u)
	oi.Product, _, err = regString(ctx, rs, productOptions, "ProductType")
	return oi, err
}

func (o osInfo) isDC() bool { return strings.EqualFold(o.Product, "LanmanNT") }

func requireDC(ctx context.Context, _ *Env, rs RegistryStore, _ Params) error {
	oi, err := readOSInfo(ctx, rs)
	if err != nil {
		return err
	}
	if !oi.isDC() {
		return errors.New("not a domain controller (ProductType is " + oi.Product + ")")
	}
	return nil
}

// lookbackDays is the event-log window for the 5829 check.
const lookbackDays = 7

func count5829(ctx context.Context, env *Env) (n int, latest time.Time, avail bool, err error) {
	if env.Win.Events == nil {
		return 0, time.Time{}, false, nil
	}
	c, err := env.Win.Events.Count(ctx, "System", []int{5829}, env.now().Add(-lookbackDays*24*time.Hour))
	return c.N, c.Latest, true, err
}

// ---- ad.zerologon_check (read-only) ----

type zerologonCheck struct{}

func (zerologonCheck) Spec() Spec {
	return Spec{Name: "ad.zerologon_check", Risk: RiskNone, ReadOnly: true,
		Doc: "Read-only Zerologon (CVE-2020-1472) check: build and update revision against the August 2020 fix, FullSecureChannelProtection, the vulnerable-channel allow-list, and Netlogon event 5829 in the last 7 days. Never fails because a DC is vulnerable; the verdict is in the output."}
}
func (zerologonCheck) Locks(Params) []string  { return nil }
func (zerologonCheck) Touches(Params) []Touch { return nil }
func (zerologonCheck) Plan(_ context.Context, env *Env, _ Params) (Plan, error) {
	if _, err := regStore(env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "read build, update revision and Netlogon parameters"}, nil
}
func (zerologonCheck) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}
func (zerologonCheck) Apply(ctx context.Context, env *Env, _ Params) (Output, error) {
	rs := env.Win.Reg
	oi, err := readOSInfo(ctx, rs)
	if err != nil {
		return nil, err
	}
	out := Output{"build": fmt.Sprintf("%d.%d", oi.Build, oi.UBR), "dc": fmt.Sprint(oi.isDC())}
	patched := zerologonPatched(oi.Build, oi.UBR)
	out["patched"] = patched
	fs, has, err := regUint(ctx, rs, netlogonParams, "FullSecureChannelProtection")
	if err != nil {
		return nil, err
	}
	out["full_secure_channel_protection"] = "absent"
	if has {
		out["full_secure_channel_protection"] = strconv.FormatUint(fs, 10)
	}
	_, allow, err := rs.Get(ctx, netlogonParams, "vulnerablechannelallowlist")
	if err != nil {
		return nil, err
	}
	out["vulnerable_channel_allowlist"] = fmt.Sprint(allow)
	n, latest, avail, err := count5829(ctx, env)
	if err != nil {
		out["event_5829"] = "error: " + err.Error()
	} else if avail {
		out["event_5829"] = strconv.Itoa(n)
		if n > 0 && !latest.IsZero() {
			out["event_5829_latest"] = latest.UTC().Format(time.RFC3339)
		}
	} else {
		out["event_5829"] = "unavailable"
	}
	switch {
	case !oi.isDC():
		out["verdict"] = "not a domain controller"
	case patched == "no":
		out["verdict"] = "VULNERABLE: build below the August 2020 update"
	case allow:
		out["verdict"] = "WEAK: vulnerable-channel allow-list is set"
	case patched == "yes" && has && fs == 1:
		out["verdict"] = "ok: patched and enforced"
	case patched == "yes":
		out["verdict"] = "patched, enforcement key not set (enforcement is default since Feb 2021 updates)"
	default:
		out["verdict"] = "unknown patch level: verify the August 2020 cumulative update by hotfix"
	}
	return out, nil
}
func (zerologonCheck) Verify(context.Context, *Env, Params) error { return nil }

// ---- ad.secure_channel ----

func secureChannel() Action {
	return regBundle{
		spec: Spec{Name: "ad.secure_channel", Risk: RiskLockout,
			Doc: "Enforce Netlogon FullSecureChannelProtection=1 (Zerologon). Reports the build and patch level, the vulnerable-channel allow-list and event 5829; the key only takes effect on a DC with the August 2020 update. Denies non-compliant (vulnerable) secure channels, never NTLM.",
			Params: []ParamSpec{
				{Name: "enforce", Type: Bool, Required: true},
				{Name: "report_only", Type: Bool}}},
		edits: func(p Params) ([]regEdit, []string, error) {
			v := uint64(0)
			if p.Bool("enforce") {
				v = 1
			}
			return []regEdit{{Key: netlogonParams, Name: "FullSecureChannelProtection", Val: dword(v)}}, nil, nil
		},
		pre:        requireDC,
		reportOnly: func(p Params) bool { return p.Bool("report_only") },
	}.withNotes(secureChannelNotes)
}

// withNotes wraps a bundle so its Plan adds environment-derived notes.
func (b regBundle) withNotes(f func(ctx context.Context, env *Env, p Params) ([]string, error)) Action {
	return noted{b, f}
}

type noted struct {
	regBundle
	notes func(ctx context.Context, env *Env, p Params) ([]string, error)
}

func (n noted) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	pl, err := n.regBundle.Plan(ctx, env, p)
	if err != nil {
		return pl, err
	}
	extra, err := n.notes(ctx, env, p)
	if err != nil {
		return pl, err
	}
	pl.Notes = append(pl.Notes, extra...)
	return pl, nil
}

func secureChannelNotes(ctx context.Context, env *Env, p Params) ([]string, error) {
	oi, err := readOSInfo(ctx, env.Win.Reg)
	if err != nil {
		return nil, err
	}
	var notes []string
	switch zerologonPatched(oi.Build, oi.UBR) {
	case "no":
		notes = append(notes, fmt.Sprintf("build %d.%d is below the August 2020 update: the key has no effect until the DC is patched (windows.hotfix)", oi.Build, oi.UBR))
	case "unknown":
		notes = append(notes, fmt.Sprintf("build %d.%d: patch level cannot be judged from the build number", oi.Build, oi.UBR))
	}
	if _, ok, _ := env.Win.Reg.Get(ctx, netlogonParams, "vulnerablechannelallowlist"); ok {
		notes = append(notes, "vulnerablechannelallowlist is set: it exempts machines from enforcement; review it")
	}
	if p.Bool("enforce") {
		n, latest, avail, err := count5829(ctx, env)
		switch {
		case err != nil:
			notes = append(notes, "event 5829 check failed: "+err.Error())
		case avail && n > 0:
			notes = append(notes, fmt.Sprintf("%d event(s) 5829 (vulnerable secure channel allowed) in the last %d days, latest %s: enforcement will deny those devices", n, lookbackDays, latest.UTC().Format(time.RFC3339)))
		}
	}
	return notes, nil
}

// ---- ad.dc.rpc_range ----

func parsePortRange(s string) (lo, hi int, err error) {
	a, b, ok := strings.Cut(strings.NewReplacer(":", "-", " ", "").Replace(s), "-")
	if !ok {
		return 0, 0, errors.New(`range must look like "5000-5200"`)
	}
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return 0, 0, errors.New("range bounds must be numbers")
	}
	if lo < 1024 || hi > 65535 || hi < lo {
		return 0, 0, errors.New("range must lie within 1024-65535")
	}
	if hi-lo+1 < 100 {
		return 0, 0, errors.New("range must hold at least 100 ports (a DC exhausts a smaller range)")
	}
	return lo, hi, nil
}

func rpcRange() Action {
	return regBundle{
		spec: Spec{Name: "ad.dc.rpc_range", Risk: RiskService,
			Doc: "Pin the RPC dynamic port range (HKLM\\SOFTWARE\\Microsoft\\Rpc\\Internet) to the manifest's rpc_range so the firewall can be exact. Takes effect after the RPC endpoint mapper restarts (reboot).",
			Params: []ParamSpec{{Name: "range", Type: String, Required: true, Max: 32, Check: func(v any) error {
				_, _, err := parsePortRange(v.(string))
				return err
			}}}},
		edits: func(p Params) ([]regEdit, []string, error) {
			lo, hi, err := parsePortRange(p.Str("range"))
			if err != nil {
				return nil, nil, err
			}
			return []regEdit{
				{Key: rpcInternetKey, Name: "Ports", Val: multi(fmt.Sprintf("%d-%d", lo, hi))},
				{Key: rpcInternetKey, Name: "PortsInternetAvailable", Val: sz("Y")},
				{Key: rpcInternetKey, Name: "UseInternetPorts", Val: sz("Y")},
			}, []string{"takes effect after a reboot; open the same range in the host and Palo rules"}, nil
		},
		pre: requireDC,
	}
}

// ---- windows.smb1 ----

const (
	lanmanServerParams = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	mrxsmb10Key        = `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`
	lanmanWorkstation  = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation`
)

func smb1() Action {
	return regBundle{
		spec: Spec{Name: "windows.smb1", Risk: RiskService,
			Doc:    "Disable (enabled=false) or enable the SMBv1 server and client through the registry. SMB2/3, which the scorer uses, is untouched. The client driver change needs a reboot.",
			Params: []ParamSpec{{Name: "enabled", Type: Bool, Required: true}}},
		edits: func(p Params) ([]regEdit, []string, error) {
			if p.Bool("enabled") {
				return []regEdit{
					{Key: lanmanServerParams, Name: "SMB1", Val: dword(1)},
					{Key: mrxsmb10Key, Name: "Start", Val: dword(3)},
					{Key: lanmanWorkstation, Name: "DependOnService", Val: multi("Bowser", "MRxSmb10", "MRxSmb20", "NSI")},
				}, nil, nil
			}
			return []regEdit{
				{Key: lanmanServerParams, Name: "SMB1", Val: dword(0)},
				{Key: mrxsmb10Key, Name: "Start", Val: dword(4)},
				{Key: lanmanWorkstation, Name: "DependOnService", Val: multi("Bowser", "MRxSmb20", "NSI")},
			}, []string{"the server stops answering SMB1 immediately; the client driver is off after a reboot"}, nil
		},
	}
}
