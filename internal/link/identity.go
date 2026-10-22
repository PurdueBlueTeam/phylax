package link

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Pin is the SHA-256 of a peer's DER-encoded SubjectPublicKeyInfo. It is the
// only thing authentication depends on: certificate dates, names and chains
// are ignored. The same value is what `curl --pinnedpubkey sha256//...` uses.
type Pin [sha256.Size]byte

// String returns the lowercase hex form.
func (p Pin) String() string { return hex.EncodeToString(p[:]) }

// Curl returns the curl --pinnedpubkey form, "sha256//<base64>".
func (p Pin) Curl() string { return "sha256//" + base64.StdEncoding.EncodeToString(p[:]) }

// ParsePin accepts 64 hex characters or the curl "sha256//base64" form.
func ParsePin(s string) (Pin, error) {
	var p Pin
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "sha256//"); ok {
		b, err := base64.StdEncoding.DecodeString(rest)
		if err != nil || len(b) != len(p) {
			return p, errors.New("link: bad curl-style pin")
		}
		copy(p[:], b)
		return p, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(p) {
		return p, errors.New("link: pin must be 64 hex characters or sha256//base64")
	}
	copy(p[:], b)
	return p, nil
}

// PinOfKey computes the pin of a public key.
func PinOfKey(pub *ecdsa.PublicKey) (Pin, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Pin{}, err
	}
	return Pin(sha256.Sum256(der)), nil
}

// pinOfCert returns the pin of a certificate, requiring an ECDSA P-256 key.
func pinOfCert(c *x509.Certificate) (Pin, error) {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return Pin{}, errors.New("link: peer key is not ECDSA P-256")
	}
	return Pin(sha256.Sum256(c.RawSubjectPublicKeyInfo)), nil
}

// Identity is a node's transport keypair and self-signed certificate.
type Identity struct {
	Cert tls.Certificate
	Pin  Pin
	key  *ecdsa.PrivateKey
}

// GenerateIdentity creates a fresh ECDSA P-256 identity. The certificate is
// valid for ten years starting a day ago so stock clients that do check dates
// are not tripped by modest clock skew; Phylax itself ignores dates.
func GenerateIdentity(name string) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return identityFromKey(key, name)
}

func identityFromKey(key *ecdsa.PrivateKey, name string) (*Identity, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pin, err := PinOfKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, Pin: pin, key: key}, nil
}

// Marshal encodes the identity as PEM (EC PRIVATE KEY then CERTIFICATE).
func (id *Identity) Marshal() ([]byte, error) {
	kb, err := x509.MarshalECPrivateKey(id.key)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Cert.Certificate[0]})...)
	return out, nil
}

// ParseIdentity decodes the output of Marshal.
func ParseIdentity(data []byte) (*Identity, error) {
	var key *ecdsa.PrivateKey
	var certDER []byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("link: parse key: %w", err)
			}
			key = k
		case "CERTIFICATE":
			certDER = b.Bytes
		}
	}
	if key == nil || certDER == nil {
		return nil, errors.New("link: identity file needs a key and a certificate")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("link: identity key is not P-256")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	cp, err := pinOfCert(cert)
	if err != nil {
		return nil, err
	}
	kp, err := PinOfKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if cp != kp {
		return nil, errors.New("link: certificate does not match private key")
	}
	return &Identity{Cert: tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, Pin: kp, key: key}, nil
}

// LoadOrCreateIdentity reads the identity at path, or generates and saves a
// new one (atomically, mode 0600) if the file does not exist.
func LoadOrCreateIdentity(path, name string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ParseIdentity(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := GenerateIdentity(name)
	if err != nil {
		return nil, err
	}
	b, err := id.Marshal()
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, b, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-identity-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil && !isWindows() {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
