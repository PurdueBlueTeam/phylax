//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-ole/go-ole/oleutil"
)

// Account creation for ad.honey_account over ADSI (IADsContainer.Create). Like
// the rest of the ADSI backend it is untested without a domain controller:
// needs a lab run.

const (
	uacNormalAccount   = 0x200
	uacDontRequirePre  = 0x400000
	uacAccountDisabled = 0x2
)

// HoneyAccountExists implements HoneyADBackend.
func (a ADSI) HoneyAccountExists(ctx context.Context, name string) (bool, error) {
	_, ok, err := a.Find(ctx, name)
	return ok, err
}

// CreateHoneyAccount implements HoneyADBackend. The account is created
// disabled, given its password, and enabled last, so there is never a moment
// with an enabled account that has no password. It is a plain user: no group
// memberships are added, so it holds only the rights of Domain Users.
func (ADSI) CreateHoneyAccount(_ context.Context, h HoneyAccount) error {
	if h.Name == "" || h.OU == "" {
		return errors.New("honey account needs a name and an OU")
	}
	return com(func() error {
		ou, err := adsBind(dnPath(h.OU))
		if err != nil {
			return fmt.Errorf("bind OU: %w", err)
		}
		defer ou.Release()
		uv, err := oleutil.CallMethod(ou, "Create", "user", "CN="+h.Name)
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		defer uv.Clear()
		u := uv.ToIDispatch()
		if u == nil {
			return errors.New("create user: no object returned")
		}
		put := func(prop string, v any) error {
			_, err := oleutil.CallMethod(u, "Put", prop, v)
			return err
		}
		if err := put("sAMAccountName", h.Name); err != nil {
			return err
		}
		if h.Description != "" {
			if err := put("description", h.Description); err != nil {
				return err
			}
		}
		if err := put("userAccountControl", int32(uacNormalAccount|uacAccountDisabled)); err != nil {
			return err
		}
		if err := setInfo(u); err != nil {
			return fmt.Errorf("save new account: %w", err)
		}
		if _, err := oleutil.CallMethod(u, "SetPassword", h.Password); err != nil {
			// Do not leave a passwordless account behind.
			_, _ = oleutil.CallMethod(u, "DeleteObject", int32(0))
			return fmt.Errorf("set password: %w", errors.New("rejected by the domain (password policy?)"))
		}
		if h.SPN != "" {
			if err := put("servicePrincipalName", h.SPN); err != nil {
				return err
			}
		}
		uac := int32(uacNormalAccount)
		if h.DontRequirePreauth {
			uac |= uacDontRequirePre
		}
		if !h.Enabled {
			uac |= uacAccountDisabled
		}
		if err := put("userAccountControl", uac); err != nil {
			return err
		}
		return setInfo(u)
	})
}

var _ HoneyADBackend = ADSI{}
