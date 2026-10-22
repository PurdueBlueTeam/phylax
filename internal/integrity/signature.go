package integrity

import (
	"context"
	"errors"
	"strings"
)

// SigStatus is the outcome of an Authenticode / catalog verification.
type SigStatus string

const (
	SigValid       SigStatus = "valid"
	SigUnsigned    SigStatus = "unsigned"
	SigBad         SigStatus = "invalid" // signed but verification failed (tampered, untrusted chain, ...)
	SigUnsupported SigStatus = "unsupported"
)

// SignatureResult is what a SignatureVerifier reports.
type SignatureResult struct {
	Status  SigStatus
	Signer  string // leaf certificate subject
	Catalog string // catalog file when the signature came from a catalog
	Detail  string
}

// SignatureVerifier verifies Authenticode (embedded or catalog) signatures.
// The Windows implementation uses WinVerifyTrust; elsewhere NewSystemVerifier
// reports SigUnsupported. Tests and the controller can supply their own.
type SignatureVerifier interface {
	VerifyFile(ctx context.Context, path string) (SignatureResult, error)
}

// ErrSignatureUnsupported is returned by verifiers on platforms without
// Authenticode.
var ErrSignatureUnsupported = errors.New("integrity: authenticode verification not supported on this platform")

// SignerAllowlist is the manifest's list of acceptable third-party signers
// (Splunk, SQL Server, Sysinternals, ...). Matching is case-insensitive
// substring on the certificate subject.
type SignerAllowlist []string

// Allows reports whether signer is allowed.
func (a SignerAllowlist) Allows(signer string) bool {
	s := strings.ToLower(signer)
	if s == "" {
		return false
	}
	for _, w := range a {
		if w != "" && strings.Contains(s, strings.ToLower(w)) {
			return true
		}
	}
	return false
}
