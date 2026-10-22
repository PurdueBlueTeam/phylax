package creds

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// BreakGlassLength is the fixed length of derived passwords.
const BreakGlassLength = 24

// NewBreakGlassSecret makes a 160-bit secret in a printable, typeable form
// (RFC 4648 base32 in groups of five: XXXXX-XXXXX-...). Print it and keep it
// off the controller; Derive reproduces every unscored password from it.
func NewBreakGlassSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	var parts []string
	for i := 0; i < len(s); i += 5 {
		parts = append(parts, s[i:min(i+5, len(s))])
	}
	return strings.Join(parts, "-"), nil
}

func normalizeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) < 26 { // 130 bits of base32
		return nil, errors.New("creds: break-glass secret too short (need at least 26 base32 characters)")
	}
	return []byte(s), nil
}

// DeriveBreakGlass computes the password for (host, user, epoch) as a pure
// function of the printed secret: HMAC-SHA256 keyed by the secret over a
// length-prefixed (domain-separated) encoding of the inputs, expanded with a
// counter and rejection-sampled into the conservative (Scored) charset, so it also survives DSNs, shells and CSVs. Host and user are
// lower-cased (Windows names are case-insensitive and humans retype them);
// the epoch changes with every restore (design: "a new epoch"), so a stale
// printed sheet does not match a re-rolled controller.
//
// The result always satisfies the conservative content rules (all four
// character kinds, alphanumeric ends). It is intentionally not usable for
// scored accounts: those stay under PCR, where the scorer must also be told.
func DeriveBreakGlass(secret, host, user string, epoch uint32) (vault.Secret, error) {
	key, err := normalizeSecret(secret)
	if err != nil {
		return vault.Secret{}, err
	}
	defer vault.Wipe(key)
	host, user = strings.ToLower(host), strings.ToLower(user)
	if host == "" || user == "" {
		return vault.Secret{}, errors.New("creds: break-glass needs host and user")
	}
	var msg []byte
	msg = append(msg, "phylax-breakglass-v1"...)
	msg = binary.BigEndian.AppendUint32(msg, epoch)
	for _, f := range []string{host, user} {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(f)))
		msg = append(msg, f...)
	}
	set := Scored.Charset()
	limit := 256 - 256%len(set)
	for attempt := uint32(0); attempt < 1000; attempt++ {
		out := make([]byte, 0, BreakGlassLength)
		for block := uint32(0); len(out) < BreakGlassLength; block++ {
			m := hmac.New(sha256.New, key)
			m.Write(msg)
			m.Write(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, attempt), block))
			for _, b := range m.Sum(nil) {
				if int(b) < limit && len(out) < BreakGlassLength {
					out = append(out, set[int(b)%len(set)])
				}
			}
			if block > 64 {
				break
			}
		}
		if len(out) == BreakGlassLength && Scored.checkContent(string(out)) == nil {
			s := vault.NewSecret(out)
			vault.Wipe(out)
			return s, nil
		}
		vault.Wipe(out)
	}
	return vault.Secret{}, errors.New("creds: derivation failed")
}
