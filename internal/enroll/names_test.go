package enroll

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

func TestHostNameSecretPerController(t *testing.T) {
	a := newEnroller(t)
	b := newEnroller(t)
	sa, err := a.e.HostNameSecret("h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sa) != 32 {
		t.Fatalf("secret is %d bytes, want 32", len(sa))
	}
	again, err := a.e.HostNameSecret("h1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, again) {
		t.Fatal("the same controller gave two different secrets for one host")
	}
	sb, err := b.e.HostNameSecret("h1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sa, sb) {
		t.Fatal("two controllers gave the same secret for one host")
	}
	if na, nb := svcinstall.DeriveNames(sa), svcinstall.DeriveNames(sb); na.Dir == nb.Dir || na.Binary == nb.Binary {
		t.Fatalf("two controllers derive the same install names: %+v vs %+v", na, nb)
	}
	path := filepath.Join(a.dir, "name_secret")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("name_secret mode = %o, want 600", fi.Mode().Perm())
	}
	// A new Enroller over the same data dir keeps the controller's secret, so
	// later pushes land on the same randomised paths.
	a2 := newEnrollerAt(t, a.dir, nil)
	s2, err := a2.e.HostNameSecret("h1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, s2) {
		t.Fatal("the secret did not survive a reload")
	}
}
