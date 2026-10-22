//go:build windows

package integrity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWintrust                   = windows.NewLazySystemDLL("wintrust.dll")
	procCryptCATAdminAcquire      = modWintrust.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminRelease      = modWintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHash     = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminEnumCatalog  = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCat   = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfo       = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
	procWTHelperProvDataFromState = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSigner     = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
)

// wintrustCatalogInfo mirrors WINTRUST_CATALOG_INFO.
type wintrustCatalogInfo struct {
	Size                 uint32
	CatalogVersion       uint32
	CatalogFilePath      *uint16
	MemberTag            *uint16
	MemberFilePath       *uint16
	MemberFile           windows.Handle
	CalculatedFileHash   *byte
	CalculatedFileHashSz uint32
	CatalogContext       uintptr
	CatAdmin             windows.Handle
}

// catalogInfo mirrors CATALOG_INFO.
type catalogInfo struct {
	Size        uint32
	CatalogFile [260]uint16
}

type windowsVerifier struct{}

// NewSystemVerifier returns a WinVerifyTrust-backed verifier. Embedded
// Authenticode signatures are tried first, then catalog signatures (which is
// how most Windows system binaries are signed). Revocation checks are off so
// verification works on the competition's offline network.
func NewSystemVerifier() SignatureVerifier { return windowsVerifier{} }

func (windowsVerifier) VerifyFile(ctx context.Context, path string) (SignatureResult, error) {
	if err := ctx.Err(); err != nil {
		return SignatureResult{}, err
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return SignatureResult{}, err
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p16}
	res, verr := winVerify(windows.WTD_CHOICE_FILE, unsafe.Pointer(fi))
	if verr == nil {
		return res, nil
	}
	if isNoSignature(verr) {
		if cr, ok, cerr := verifyViaCatalog(path); cerr == nil && ok {
			return cr, nil
		}
		return SignatureResult{Status: SigUnsigned, Detail: verr.Error()}, nil
	}
	res.Status = SigBad
	res.Detail = verr.Error()
	return res, nil
}

func isNoSignature(err error) bool {
	var en windows.Errno
	if !errors.As(err, &en) {
		return false
	}
	switch windows.Handle(en) {
	case windows.TRUST_E_NOSIGNATURE, windows.TRUST_E_SUBJECT_FORM_UNKNOWN, windows.TRUST_E_PROVIDER_UNKNOWN:
		return true
	}
	return false
}

// winVerify runs WinVerifyTrustEx over a file or catalog info block and, on
// success, extracts the leaf signer subject from the provider data.
func winVerify(choice uint32, info unsafe.Pointer) (SignatureResult, error) {
	d := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, d)
	var res SignatureResult
	if verr == nil {
		res.Status = SigValid
		res.Signer = signerFromState(d.StateData)
	}
	d.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, d)
	return res, verr
}

// signerFromState walks CRYPT_PROVIDER_DATA -> CRYPT_PROVIDER_SGNR ->
// CRYPT_PROVIDER_CERT[0] (the leaf) and returns its simple display name.
func signerFromState(state windows.Handle) string {
	if state == 0 {
		return ""
	}
	pd, _, _ := procWTHelperProvDataFromState.Call(uintptr(state))
	if pd == 0 {
		return ""
	}
	sg, _, _ := procWTHelperGetProvSigner.Call(pd, 0, 0, 0)
	if sg == 0 {
		return ""
	}
	// CRYPT_PROVIDER_SGNR: cbStruct u32, sftVerifyAsOf FILETIME(8), csCertChain u32, pasCertChain *CRYPT_PROVIDER_CERT.
	type sgnrHead struct {
		Size        uint32
		VerifyAsOf  windows.Filetime
		CsCertChain uint32
		PasCertCh   unsafe.Pointer
	}
	sh := (*sgnrHead)(*(*unsafe.Pointer)(unsafe.Pointer(&sg)))
	if sh.CsCertChain == 0 || sh.PasCertCh == nil {
		return ""
	}
	// CRYPT_PROVIDER_CERT: cbStruct u32, pCert *CERT_CONTEXT.
	type provCert struct {
		Size uint32
		Cert *windows.CertContext
	}
	pc := (*provCert)(sh.PasCertCh)
	if pc.Cert == nil {
		return ""
	}
	n := windows.CertGetNameString(pc.Cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(pc.Cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], n)
	return windows.UTF16ToString(buf)
}

// verifyViaCatalog hashes the file, finds a catalog that lists the hash and
// verifies the file against it.
func verifyViaCatalog(path string) (SignatureResult, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return SignatureResult{}, false, err
	}
	defer f.Close()
	var admin windows.Handle
	if r, _, e := procCryptCATAdminAcquire.Call(uintptr(unsafe.Pointer(&admin)), 0, 0); r == 0 {
		return SignatureResult{}, false, e
	}
	defer procCryptCATAdminRelease.Call(uintptr(admin), 0)
	h := windows.Handle(f.Fd())
	var hashLen uint32
	procCryptCATAdminCalcHash.Call(uintptr(h), uintptr(unsafe.Pointer(&hashLen)), 0, 0)
	if hashLen == 0 || hashLen > 128 {
		return SignatureResult{}, false, errors.New("catalog hash length")
	}
	hash := make([]byte, hashLen)
	if r, _, e := procCryptCATAdminCalcHash.Call(uintptr(h), uintptr(unsafe.Pointer(&hashLen)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return SignatureResult{}, false, e
	}
	cat, _, _ := procCryptCATAdminEnumCatalog.Call(uintptr(admin), uintptr(unsafe.Pointer(&hash[0])), uintptr(hashLen), 0, 0)
	if cat == 0 {
		return SignatureResult{}, false, nil
	}
	defer procCryptCATAdminReleaseCat.Call(uintptr(admin), cat, 0)
	ci := catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
	if r, _, e := procCryptCATCatalogInfo.Call(cat, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
		return SignatureResult{}, false, e
	}
	var tag strings.Builder
	for _, b := range hash {
		fmt.Fprintf(&tag, "%02X", b)
	}
	tag16, _ := windows.UTF16PtrFromString(tag.String())
	p16, _ := windows.UTF16PtrFromString(path)
	wci := wintrustCatalogInfo{
		Size: uint32(unsafe.Sizeof(wintrustCatalogInfo{})), CatalogFilePath: &ci.CatalogFile[0],
		MemberTag: tag16, MemberFilePath: p16, MemberFile: h,
		CalculatedFileHash: &hash[0], CalculatedFileHashSz: hashLen, CatAdmin: admin,
	}
	res, verr := winVerify(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&wci))
	res.Catalog = windows.UTF16ToString(ci.CatalogFile[:])
	if verr != nil {
		res.Status = SigBad
		res.Detail = verr.Error()
		return res, true, nil
	}
	return res, true, nil
}
