//go:build !windows

package integrity

import "context"

type unsupportedVerifier struct{}

func (unsupportedVerifier) VerifyFile(context.Context, string) (SignatureResult, error) {
	return SignatureResult{Status: SigUnsupported}, ErrSignatureUnsupported
}

// NewSystemVerifier returns the platform verifier; on non-Windows hosts it
// reports SigUnsupported.
func NewSystemVerifier() SignatureVerifier { return unsupportedVerifier{} }
