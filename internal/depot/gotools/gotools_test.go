package gotools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLSAndHash(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, ".hidden"), []byte("abc"), 0o600)
	os.Symlink("/etc/passwd", filepath.Join(d, "link"))
	fs, err := List(d)
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Name != ".hidden" || fs[0].Size != 3 || fs[1].Target != "/etc/passwd" {
		t.Fatalf("%+v", fs)
	}
	var b bytes.Buffer
	FormatLS(&b, fs)
	if !strings.Contains(b.String(), "link -> /etc/passwd") {
		t.Fatal(b.String())
	}
	want := sha256.Sum256([]byte("abc"))
	got, err := HashFile(filepath.Join(d, ".hidden"))
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatal(got, err)
	}
	b.Reset()
	if err := Hash(&b, []string{filepath.Join(d, "nope")}); err == nil {
		t.Fatal("missing file not reported")
	}
}
