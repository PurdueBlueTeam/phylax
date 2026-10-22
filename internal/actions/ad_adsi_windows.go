//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// ADSI implements ADBackend through Active Directory Service Interfaces (late
// bound IDispatch via go-ole; pure Go, no cgo, no PowerShell). The DC's agent
// runs as SYSTEM, which binds with the machine's domain credentials. Group
// membership uses IADsGroup.Add/Remove, passwords IADsUser.SetPassword.
// Searching goes through the ADsDSOObject OLE DB provider (ADO). Untested
// without a domain controller: needs a lab run.
type ADSI struct{}

var (
	modActiveDS     = windows.NewLazySystemDLL("activeds.dll")
	procADsGetObjct = modActiveDS.NewProc("ADsGetObject")
)

const (
	uacAccountDisable = 0x2
	adMaxRows         = 5000
)

// com runs fn on a locked OS thread with COM initialised (apartment model).
func com(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oerr, ok := err.(*ole.OleError); !ok || (oerr.Code() != 1 && oerr.Code() != 0x80010106) {
			return fmt.Errorf("CoInitializeEx: %w", err)
		}
	}
	defer ole.CoUninitialize()
	return fn()
}

func adsBind(path string) (*ole.IDispatch, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var out unsafe.Pointer
	r, _, _ := procADsGetObjct.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(ole.IID_IDispatch)), uintptr(unsafe.Pointer(&out)))
	if int32(r) < 0 {
		return nil, fmt.Errorf("ADsGetObject %s: HRESULT 0x%08x", path, uint32(r))
	}
	return (*ole.IDispatch)(out), nil
}

func ldapEscape(s string) string {
	return strings.NewReplacer(`\`, `\5c`, `*`, `\2a`, `(`, `\28`, `)`, `\29`, "\x00", `\00`).Replace(s)
}

func dnPath(dn string) string {
	return "LDAP://" + strings.NewReplacer("/", `\/`).Replace(dn)
}

func variantStrings(v *ole.VARIANT) []string {
	switch x := v.Value().(type) {
	case string:
		return []string{x}
	case nil:
		return nil
	}
	if v.VT&ole.VT_ARRAY == 0 {
		return nil
	}
	arr := v.ToArray()
	if arr == nil {
		return nil
	}
	defer arr.Release()
	var out []string
	for _, e := range arr.ToValueArray() {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func getProp(d *ole.IDispatch, name string) (*ole.VARIANT, bool) {
	v, err := oleutil.CallMethod(d, "Get", name)
	if err != nil {
		return nil, false // property not set on the object
	}
	return v, true
}

func getInt(d *ole.IDispatch, name string) (int64, bool) {
	v, ok := getProp(d, name)
	if !ok {
		return 0, false
	}
	defer v.Clear()
	switch n := v.Value().(type) {
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint32:
		return int64(n), true
	}
	return 0, false
}

func getLargeInt(d *ole.IDispatch, name string) time.Time {
	v, ok := getProp(d, name)
	if !ok {
		return time.Time{}
	}
	defer v.Clear()
	li := v.ToIDispatch()
	if li == nil {
		return time.Time{}
	}
	hi, err1 := oleutil.GetProperty(li, "HighPart")
	lo, err2 := oleutil.GetProperty(li, "LowPart")
	if err1 != nil || err2 != nil {
		return time.Time{}
	}
	ft := uint64(uint32(hi.Val))<<32 | uint64(uint32(lo.Val))
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME (100ns since 1601) to Unix.
	return time.Unix(0, (int64(ft)-116444736000000000)*100).UTC()
}

func sidString(d *ole.IDispatch) string {
	v, ok := getProp(d, "objectSid")
	if !ok {
		return ""
	}
	defer v.Clear()
	arr := v.ToArray()
	if arr == nil {
		return ""
	}
	defer arr.Release()
	var b []byte
	for _, e := range arr.ToValueArray() {
		if n, ok := e.(uint8); ok {
			b = append(b, n)
		}
	}
	if len(b) < 8 {
		return ""
	}
	return (*windows.SID)(unsafe.Pointer(&b[0])).String()
}

func loadObject(dn string) (ADObject, bool, error) {
	d, err := adsBind(dnPath(dn))
	if err != nil {
		if strings.Contains(err.Error(), "0x80072030") { // no such object
			return ADObject{}, false, nil
		}
		return ADObject{}, false, err
	}
	defer d.Release()
	o := ADObject{DN: dn, SID: sidString(d)}
	if v, ok := getProp(d, "sAMAccountName"); ok {
		o.SAM = v.ToString()
		v.Clear()
	}
	if v, ok := getProp(d, "objectClass"); ok {
		classes := variantStrings(v)
		v.Clear()
		o.Class = "other"
		for _, c := range classes {
			switch strings.ToLower(c) {
			case "computer":
				o.Class = "computer"
			case "group":
				o.Class = "group"
			case "user":
				if o.Class == "other" {
					o.Class = "user"
				}
			}
		}
	}
	if n, ok := getInt(d, "userAccountControl"); ok {
		o.Enabled = n&uacAccountDisable == 0
	}
	if n, ok := getInt(d, "adminCount"); ok {
		o.AdminCount = int(n)
	}
	o.PwdLastSet = getLargeInt(d, "pwdLastSet")
	if o.Class == "group" {
		if v, err := oleutil.CallMethod(d, "GetEx", "member"); err == nil {
			o.Members = variantStrings(v)
			v.Clear()
		}
	}
	return o, true, nil
}

func (ADSI) DomainDN(ctx context.Context) (string, error) {
	var dn string
	err := com(func() error {
		d, err := adsBind("LDAP://RootDSE")
		if err != nil {
			return err
		}
		defer d.Release()
		v, ok := getProp(d, "defaultNamingContext")
		if !ok {
			return errors.New("RootDSE has no defaultNamingContext")
		}
		dn = v.ToString()
		v.Clear()
		return nil
	})
	return dn, err
}

// search runs an LDAP query and returns the distinguishedNames.
func (a ADSI) search(ctx context.Context, filter string) ([]string, error) {
	base, err := a.DomainDN(ctx)
	if err != nil {
		return nil, err
	}
	var dns []string
	err = com(func() error {
		unk, err := oleutil.CreateObject("ADODB.Connection")
		if err != nil {
			return err
		}
		defer unk.Release()
		conn, err := unk.QueryInterface(ole.IID_IDispatch)
		if err != nil {
			return err
		}
		defer conn.Release()
		if _, err := oleutil.PutProperty(conn, "Provider", "ADsDSOObject"); err != nil {
			return err
		}
		if _, err := oleutil.CallMethod(conn, "Open", "Active Directory Provider"); err != nil {
			return err
		}
		defer oleutil.CallMethod(conn, "Close")
		q := fmt.Sprintf("<LDAP://%s>;%s;distinguishedName;subtree", base, filter)
		rsv, err := oleutil.CallMethod(conn, "Execute", q)
		if err != nil {
			return err
		}
		rs := rsv.ToIDispatch()
		if rs == nil {
			return errors.New("ADO returned no recordset")
		}
		defer rs.Release()
		for i := 0; i < adMaxRows; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			eof, err := oleutil.GetProperty(rs, "EOF")
			if err != nil {
				return err
			}
			if b, _ := eof.Value().(bool); b {
				break
			}
			fields, err := oleutil.GetProperty(rs, "Fields")
			if err != nil {
				return err
			}
			item, err := oleutil.GetProperty(fields.ToIDispatch(), "Item", "distinguishedName")
			if err != nil {
				return err
			}
			val, err := oleutil.GetProperty(item.ToIDispatch(), "Value")
			if err != nil {
				return err
			}
			dns = append(dns, val.ToString())
			if _, err := oleutil.CallMethod(rs, "MoveNext"); err != nil {
				return err
			}
		}
		return nil
	})
	return dns, err
}

func (a ADSI) Find(ctx context.Context, sam string) (ADObject, bool, error) {
	dns, err := a.search(ctx, fmt.Sprintf("(sAMAccountName=%s)", ldapEscape(sam)))
	if err != nil || len(dns) == 0 {
		return ADObject{}, false, err
	}
	return a.Get(ctx, dns[0])
}

func (ADSI) Get(_ context.Context, dn string) (ADObject, bool, error) {
	var (
		o  ADObject
		ok bool
	)
	err := com(func() (err error) { o, ok, err = loadObject(dn); return })
	return o, ok, err
}

func (a ADSI) AdminCountSet(ctx context.Context) ([]ADObject, error) {
	dns, err := a.search(ctx, "(&(adminCount=1)(|(objectClass=user)(objectClass=group)))")
	if err != nil {
		return nil, err
	}
	var out []ADObject
	for _, dn := range dns {
		o, ok, err := a.Get(ctx, dn)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func modify(dn string, fn func(d *ole.IDispatch) error) error {
	return com(func() error {
		d, err := adsBind(dnPath(dn))
		if err != nil {
			return err
		}
		defer d.Release()
		return fn(d)
	})
}

func setInfo(d *ole.IDispatch) error { _, err := oleutil.CallMethod(d, "SetInfo"); return err }

func (ADSI) SetEnabled(_ context.Context, dn string, enabled bool) error {
	return modify(dn, func(d *ole.IDispatch) error {
		n, _ := getInt(d, "userAccountControl")
		if enabled {
			n &^= uacAccountDisable
		} else {
			n |= uacAccountDisable
		}
		if _, err := oleutil.CallMethod(d, "Put", "userAccountControl", int32(n)); err != nil {
			return err
		}
		return setInfo(d)
	})
}

func (ADSI) SetAdminCount(_ context.Context, dn string, n int) error {
	return modify(dn, func(d *ole.IDispatch) error {
		if _, err := oleutil.CallMethod(d, "Put", "adminCount", int32(n)); err != nil {
			return err
		}
		return setInfo(d)
	})
}

func (ADSI) SetPassword(_ context.Context, dn, password string, mustChange bool) error {
	return modify(dn, func(d *ole.IDispatch) error {
		if _, err := oleutil.CallMethod(d, "SetPassword", password); err != nil {
			return err
		}
		if mustChange {
			if _, err := oleutil.CallMethod(d, "Put", "pwdLastSet", int32(0)); err != nil {
				return err
			}
			return setInfo(d)
		}
		return nil
	})
}

func (ADSI) AddMember(_ context.Context, groupDN, memberDN string) error {
	return modify(groupDN, func(d *ole.IDispatch) error {
		_, err := oleutil.CallMethod(d, "Add", dnPath(memberDN))
		if err != nil && strings.Contains(err.Error(), "0x80071392") { // already a member
			return nil
		}
		return err
	})
}

func (ADSI) RemoveMember(_ context.Context, groupDN, memberDN string) error {
	return modify(groupDN, func(d *ole.IDispatch) error {
		_, err := oleutil.CallMethod(d, "Remove", dnPath(memberDN))
		if err != nil && strings.Contains(err.Error(), "0x80071033") { // not a member
			return nil
		}
		return err
	})
}
