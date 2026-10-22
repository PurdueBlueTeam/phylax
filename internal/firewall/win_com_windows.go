//go:build windows

package firewall

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// The Windows Firewall COM API (netfw.h). INetFwPolicy2 / INetFwRule are dual
// interfaces, so late-bound IDispatch calls through go-ole (pure Go on top of
// syscall) are enough: no cgo, no PowerShell, no netsh.
const (
	fwProfileDomain  = 0x1
	fwProfilePrivate = 0x2
	fwProfilePublic  = 0x4
	fwProfileAll     = 0x7FFFFFFF

	fwDirIn  = 1
	fwDirOut = 2

	fwActionBlock = 0
	fwActionAllow = 1

	fwProtoICMPv4 = 1
	fwProtoTCP    = 6
	fwProtoUDP    = 17
	fwProtoICMPv6 = 58
	fwProtoAny    = 256
)

var winProfileBits = map[string]int32{"Domain": fwProfileDomain, "Private": fwProfilePrivate, "Public": fwProfilePublic}

type comBackend struct {
	policy *ole.IDispatch
	rules  *ole.IDispatch
	unk    *ole.IUnknown
}

// NewComBackend opens HNetCfg.FwPolicy2. The calling goroutine is locked to
// its OS thread until Close, because COM apartments are per thread.
func NewComBackend() (WinBackend, error) {
	runtime.LockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		// S_FALSE (already initialized on this thread) is fine.
		if oerr, ok := err.(*ole.OleError); !ok || (oerr.Code() != 1 && oerr.Code() != 0x80010106) {
			runtime.UnlockOSThread()
			return nil, fmt.Errorf("firewall: CoInitializeEx: %w", err)
		}
	}
	unk, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("firewall: create HNetCfg.FwPolicy2: %w", err)
	}
	pol, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		unk.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, err
	}
	rv, err := oleutil.GetProperty(pol, "Rules")
	if err != nil {
		pol.Release()
		unk.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, err
	}
	return &comBackend{policy: pol, rules: rv.ToIDispatch(), unk: unk}, nil
}

func (c *comBackend) Close() error {
	if c.rules != nil {
		c.rules.Release()
	}
	if c.policy != nil {
		c.policy.Release()
	}
	if c.unk != nil {
		c.unk.Release()
	}
	c.rules, c.policy, c.unk = nil, nil, nil
	ole.CoUninitialize()
	runtime.UnlockOSThread()
	return nil
}

func actionName(a int32) string {
	if a == fwActionAllow {
		return "Allow"
	}
	return "Block"
}

func (c *comBackend) Profiles() ([]WinProfileState, error) {
	var out []WinProfileState
	for _, n := range WinProfileNames {
		bit := winProfileBits[n]
		en, err := oleutil.GetProperty(c.policy, "FirewallEnabled", bit)
		if err != nil {
			return nil, fmt.Errorf("FirewallEnabled(%s): %w", n, err)
		}
		in, err := oleutil.GetProperty(c.policy, "DefaultInboundAction", bit)
		if err != nil {
			return nil, fmt.Errorf("DefaultInboundAction(%s): %w", n, err)
		}
		o, err := oleutil.GetProperty(c.policy, "DefaultOutboundAction", bit)
		if err != nil {
			return nil, fmt.Errorf("DefaultOutboundAction(%s): %w", n, err)
		}
		out = append(out, WinProfileState{Name: n, Enabled: variantBool(en.Value()),
			DefaultInbound: actionName(variantInt(in.Value())), DefaultOutbound: actionName(variantInt(o.Value()))})
		en.Clear()
		in.Clear()
		o.Clear()
	}
	return out, nil
}

func (c *comBackend) SetProfile(p WinProfileState) error {
	bit, ok := winProfileBits[p.Name]
	if !ok {
		return fmt.Errorf("unknown profile %q", p.Name)
	}
	act := func(s string) int32 {
		if s == "Allow" {
			return fwActionAllow
		}
		return fwActionBlock
	}
	if _, err := oleutil.PutProperty(c.policy, "DefaultInboundAction", bit, act(p.DefaultInbound)); err != nil {
		return err
	}
	if _, err := oleutil.PutProperty(c.policy, "DefaultOutboundAction", bit, act(p.DefaultOutbound)); err != nil {
		return err
	}
	_, err := oleutil.PutProperty(c.policy, "FirewallEnabled", bit, p.Enabled)
	return err
}

func (c *comBackend) Rules() ([]WinRuleState, error) {
	var out []WinRuleState
	err := oleutil.ForEach(c.rules, func(v *ole.VARIANT) error {
		d := v.ToIDispatch()
		if d == nil {
			return nil
		}
		r, err := readComRule(d)
		if err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func strProp(d *ole.IDispatch, name string) (string, error) {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	defer v.Clear()
	if s, ok := v.Value().(string); ok {
		return s, nil
	}
	return "", nil
}

func intProp(d *ole.IDispatch, name string) (int32, error) {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	defer v.Clear()
	return variantInt(v.Value()), nil
}

func variantInt(x interface{}) int32 {
	switch n := x.(type) {
	case int32:
		return n
	case int64:
		return int32(n)
	case int16:
		return int32(n)
	case uint32:
		return int32(n)
	case int:
		return int32(n)
	}
	return 0
}

func variantBool(x interface{}) bool {
	b, _ := x.(bool)
	return b
}

func readComRule(d *ole.IDispatch) (WinRuleState, error) {
	var r WinRuleState
	var err error
	if r.Name, err = strProp(d, "Name"); err != nil {
		return r, err
	}
	r.Description, _ = strProp(d, "Description")
	if r.Group, err = strProp(d, "Grouping"); err != nil {
		return r, err
	}
	dir, err := intProp(d, "Direction")
	if err != nil {
		return r, err
	}
	r.Direction = map[int32]string{fwDirIn: "Inbound", fwDirOut: "Outbound"}[dir]
	act, err := intProp(d, "Action")
	if err != nil {
		return r, err
	}
	r.Action = actionName(act)
	proto, err := intProp(d, "Protocol")
	if err != nil {
		return r, err
	}
	switch proto {
	case fwProtoTCP:
		r.Protocol = "TCP"
	case fwProtoUDP:
		r.Protocol = "UDP"
	case fwProtoICMPv4:
		r.Protocol = "ICMPv4"
	case fwProtoICMPv6:
		r.Protocol = "ICMPv6"
	case fwProtoAny:
		r.Protocol = "Any"
	default:
		r.Protocol = strconv.Itoa(int(proto))
	}
	if r.Protocol == "TCP" || r.Protocol == "UDP" { // ports are only readable for these
		lp, _ := strProp(d, "LocalPorts")
		rp, _ := strProp(d, "RemotePorts")
		r.LocalPorts, r.RemotePorts = NormPorts(lp), NormPorts(rp)
	}
	ra, _ := strProp(d, "RemoteAddresses")
	if r.RemoteAddresses, err = NormAddrs(ra); err != nil {
		r.RemoteAddresses = strings.ToLower(ra) // unparsable foreign value: keep, it will just differ
	}
	if r.Protocol == "ICMPv4" || r.Protocol == "ICMPv6" {
		r.ICMPTypes, _ = strProp(d, "IcmpTypesAndCodes")
	}
	pr, err := intProp(d, "Profiles")
	if err != nil {
		return r, err
	}
	if pr == fwProfileAll || pr == fwProfileDomain|fwProfilePrivate|fwProfilePublic {
		r.Profiles = "Any"
	} else {
		r.Profiles = strconv.Itoa(int(pr))
	}
	ev, err := oleutil.GetProperty(d, "Enabled")
	if err != nil {
		return r, err
	}
	r.Enabled = variantBool(ev.Value())
	ev.Clear()
	return r, nil
}

func (c *comBackend) writeRule(d *ole.IDispatch, r WinRuleState) error {
	put := func(name string, v interface{}) error {
		_, err := oleutil.PutProperty(d, name, v)
		if err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
		return nil
	}
	proto := map[string]int32{"TCP": fwProtoTCP, "UDP": fwProtoUDP, "ICMPv4": fwProtoICMPv4, "ICMPv6": fwProtoICMPv6, "Any": fwProtoAny}[r.Protocol]
	if proto == 0 {
		return fmt.Errorf("bad protocol %q", r.Protocol)
	}
	dir := int32(fwDirIn)
	if r.Direction == "Outbound" {
		dir = fwDirOut
	}
	act := int32(fwActionBlock)
	if r.Action == "Allow" {
		act = fwActionAllow
	}
	// Protocol first: ports are only accepted once it is TCP or UDP.
	steps := []struct {
		n string
		v interface{}
	}{
		{"Name", r.Name}, {"Description", r.Description}, {"Grouping", r.Group},
		{"Direction", dir}, {"Protocol", proto}, {"Action", act},
		{"Profiles", int32(fwProfileAll)},
	}
	for _, s := range steps {
		if err := put(s.n, s.v); err != nil {
			return err
		}
	}
	if r.Protocol == "TCP" || r.Protocol == "UDP" {
		lp, rp := r.LocalPorts, r.RemotePorts
		if lp == "" {
			lp = "*"
		}
		if rp == "" {
			rp = "*"
		}
		if err := put("LocalPorts", lp); err != nil {
			return err
		}
		if err := put("RemotePorts", rp); err != nil {
			return err
		}
	}
	if err := put("RemoteAddresses", ComAddr(r.RemoteAddresses)); err != nil {
		return err
	}
	if r.ICMPTypes != "" {
		if err := put("IcmpTypesAndCodes", r.ICMPTypes); err != nil {
			return err
		}
	}
	return put("Enabled", r.Enabled)
}

func (c *comBackend) AddRule(r WinRuleState) error {
	unk, err := oleutil.CreateObject("HNetCfg.FWRule")
	if err != nil {
		return err
	}
	defer unk.Release()
	d, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer d.Release()
	if err := c.writeRule(d, r); err != nil {
		return err
	}
	_, err = oleutil.CallMethod(c.rules, "Add", d)
	return err
}

func (c *comBackend) UpdateRule(r WinRuleState) error {
	v, err := oleutil.CallMethod(c.rules, "Item", r.Name)
	if err != nil {
		return err
	}
	defer v.Clear()
	d := v.ToIDispatch()
	if d == nil {
		return fmt.Errorf("rule %q not found", r.Name)
	}
	// Disable while rewriting so a half-written rule never filters; the
	// final Enabled write restores the intended state.
	if _, err := oleutil.PutProperty(d, "Enabled", false); err != nil {
		return err
	}
	return c.writeRule(d, r)
}

func (c *comBackend) RemoveRule(name string) error {
	_, err := oleutil.CallMethod(c.rules, "Remove", name)
	return err
}
