//go:build linux

package atomicfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func trySetXattr(t *testing.T, p, name string, v []byte) {
	t.Helper()
	if err := unix.Lsetxattr(p, name, v, 0); err != nil {
		t.Skipf("xattr %s not supported here: %v", name, err)
	}
}

func getXattr(t *testing.T, p, name string) []byte {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(p, name, buf)
	if err != nil {
		t.Fatalf("getxattr: %v", err)
	}
	return buf[:n]
}

// The copy path is exercised with a user.* attribute (settable without
// privilege); the real security.selinux name is tried separately below.
func TestLabelCopyPath(t *testing.T) {
	old := labelXattr
	labelXattr = "user.phylax_label"
	defer func() { labelXattr = old }()

	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("a"), 0600)
	trySetXattr(t, p, labelXattr, []byte("system_u:object_r:test_t:s0"))
	if err := WriteFile(p, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := getXattr(t, p, labelXattr); !bytes.Equal(got, []byte("system_u:object_r:test_t:s0")) {
		t.Fatalf("label not preserved: %q", got)
	}
}

func TestSELinuxLabelPreserved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("a"), 0600)
	want := []byte("system_u:object_r:tmp_t:s0")
	if err := unix.Lsetxattr(p, "security.selinux", want, 0); err != nil {
		t.Skipf("security.selinux not settable here (no SELinux or not root): %v", err)
	}
	if err := WriteFile(p, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := getXattr(t, p, "security.selinux"); !bytes.Equal(got, want) {
		t.Fatalf("selinux label lost: %q", got)
	}
}

func TestSetuidBitPreserved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("a"), 0600)
	if err := os.Chmod(p, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode()&os.ModeSetuid == 0 || st.Mode().Perm() != 0755 {
		t.Fatalf("mode %v", st.Mode())
	}
}
