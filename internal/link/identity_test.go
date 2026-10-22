package link

import (
	"path/filepath"
	"testing"
)

func TestIdentityRoundTripAndPins(t *testing.T) {
	id, err := GenerateIdentity("x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := id.Marshal()
	id2, err := ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if id.Pin != id2.Pin {
		t.Fatal("pin changed across marshal")
	}
	for _, s := range []string{id.Pin.String(), id.Pin.Curl()} {
		p, err := ParsePin(s)
		if err != nil || p != id.Pin {
			t.Fatalf("ParsePin(%q) = %v, %v", s, p, err)
		}
	}
	for _, bad := range []string{"", "zz", "sha256//AAAA", id.Pin.String()[:62]} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q) accepted", bad)
		}
	}
	other, _ := GenerateIdentity("y")
	if other.Pin == id.Pin {
		t.Fatal("two identities share a pin")
	}
}

func TestLoadOrCreateIdentityPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "id.pem")
	a, err := LoadOrCreateIdentity(p, "n")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateIdentity(p, "n")
	if err != nil {
		t.Fatal(err)
	}
	if a.Pin != b.Pin {
		t.Fatal("identity not stable across loads")
	}
}

func TestParseIdentityRejectsMismatchedCert(t *testing.T) {
	a, _ := GenerateIdentity("a")
	b, _ := GenerateIdentity("b")
	ab, _ := a.Marshal()
	bb, _ := b.Marshal()
	// key of a + cert of b
	ka := ab[:len(ab)-len(certPart(ab))]
	if _, err := ParseIdentity(append(append([]byte{}, ka...), certPart(bb)...)); err == nil {
		t.Fatal("accepted a certificate that does not match the key")
	}
}

func certPart(pem []byte) []byte {
	const marker = "-----BEGIN CERTIFICATE-----"
	for i := 0; i+len(marker) <= len(pem); i++ {
		if string(pem[i:i+len(marker)]) == marker {
			return pem[i:]
		}
	}
	return nil
}
