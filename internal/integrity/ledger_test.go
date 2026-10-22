package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFiles() []fxFile {
	return []fxFile{
		{Path: "/usr/sbin/postfix", Data: "real postfix binary", Mode: 0o755},
		{Path: "/usr/sbin/nologin", Data: "real nologin", Mode: 0o755},
		{Path: "/usr/bin/su", Data: "su binary", Mode: 0o4755},
		{Path: "/usr/sbin/postfix-link", Link: "/usr/sbin/postfix", Mode: 0o755},
	}
}

func TestReadDebAllCompressions(t *testing.T) {
	dir := t.TempDir()
	for _, comp := range []string{"gz", "xz", "zst", ""} {
		p := filepath.Join(dir, "postfix_"+comp+".deb")
		if err := os.WriteFile(p, makeDeb(t, "postfix", "3.6.4-1", comp, testFiles()), 0o644); err != nil {
			t.Fatal(err)
		}
		pkg, err := ReadDebFile(p, ReadLimits{})
		if err != nil {
			t.Fatalf("%s: %v", comp, err)
		}
		if pkg.Name != "postfix" || pkg.Version != "3.6.4-1" || pkg.Arch != "amd64" {
			t.Fatalf("%s: control parsed as %+v", comp, pkg)
		}
		got := map[string]Entry{}
		for _, e := range pkg.Entries {
			got[e.Path] = e
		}
		if len(got) != 4 { // symlink and dir skipped, hardlink kept
			t.Fatalf("%s: entries %v", comp, got)
		}
		if got["/usr/sbin/postfix"].SHA256 != sumOf("real postfix binary") || got["/usr/sbin/postfix-link"].SHA256 != sumOf("real postfix binary") {
			t.Fatalf("%s: wrong hashes", comp)
		}
		if got["/usr/bin/su"].Mode != 0o4755 || got["/usr/bin/su"].Size != 9 || got["/usr/bin/su"].Package != "postfix" {
			t.Fatalf("%s: su entry %+v", comp, got["/usr/bin/su"])
		}
	}
}

func TestReadDebRejectsGarbageAndBombs(t *testing.T) {
	if _, err := ReadDeb(strings.NewReader("not a deb at all"), ReadLimits{}); err == nil {
		t.Fatal("garbage accepted")
	}
	big := []fxFile{{Path: "/usr/bin/big", Data: strings.Repeat("A", 1<<20), Mode: 0o755}}
	if _, err := ReadDeb(strings.NewReader(string(makeDeb(t, "b", "1", "xz", big))), ReadLimits{MaxDecompressed: 64 << 10}); err == nil {
		t.Fatal("decompression limit not enforced")
	}
}

func TestReadRPMAllCompressions(t *testing.T) {
	files := []fxFile{
		{Path: "/usr/bin/bash", Data: "bash bytes", Mode: 0o755},
		{Path: "/usr/bin/sh", Link: "/usr/bin/bash", Mode: 0o755},
		{Path: "/usr/sbin/crond", Data: "cron!", Mode: 0o755},
	}
	// hardlink entry must precede the data-carrying one in cpio.
	files[0], files[1] = files[1], files[0]
	for _, comp := range []string{"gz", "xz", "zst", ""} {
		p := filepath.Join(t.TempDir(), "x.rpm")
		os.WriteFile(p, makeRPM(t, "bash", "5.1.8", "6.el9", comp, files), 0o644)
		pkg, err := ReadRPMFile(p, ReadLimits{})
		if err != nil {
			t.Fatalf("%s: %v", comp, err)
		}
		if pkg.Name != "bash" || pkg.Version != "5.1.8-6.el9" {
			t.Fatalf("%s: %+v", comp, pkg)
		}
		got := map[string]Entry{}
		for _, e := range pkg.Entries {
			got[e.Path] = e
		}
		if got["/usr/bin/bash"].SHA256 != sumOf("bash bytes") || got["/usr/bin/sh"].SHA256 != sumOf("bash bytes") || got["/usr/sbin/crond"].SHA256 != sumOf("cron!") {
			t.Fatalf("%s: wrong hashes: %v", comp, got)
		}
		if len(got) != 3 {
			t.Fatalf("%s: entries %v", comp, got)
		}
	}
}

func buildTestLedger(t *testing.T) *Ledger {
	t.Helper()
	b := NewBuilder(Meta{Name: "t", OS: "debian12"})
	deb, err := ReadDeb(strings.NewReader(string(makeDeb(t, "postfix", "3.6.4-1", "xz", testFiles()))), ReadLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b.AddPackage(deb, "debian12", SourceVendorPackage)
	rp, err := ReadRPM(strings.NewReader(string(makeRPM(t, "dns", "1.0", "1", "gz", []fxFile{{Path: "/usr/sbin/named", Data: "named", Mode: 0o755}}))), ReadLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b.AddPackage(rp, "rocky9", SourceReference)
	l := b.Ledger()
	l.AddBad(sumOf("sliver implant"), "sliver")
	return l
}

func TestLedgerLookupAndJudge(t *testing.T) {
	l := buildTestLedger(t)
	if got := l.ByPath("/sbin/postfix"); len(got) != 1 || got[0].Package != "postfix" { // usr-merge folding
		t.Fatalf("ByPath: %+v", got)
	}
	if got := l.ByHash(sumOf("real nologin")); len(got) != 1 || got[0].Path != "/usr/sbin/nologin" {
		t.Fatalf("ByHash: %+v", got)
	}
	cases := []struct {
		path, content string
		claimed       string
		want          Verdict
	}{
		{"/usr/sbin/postfix", "real postfix binary", "", Match},
		{"/usr/sbin/postfix", "real postfix binary", "3.6.4-1", Match},
		{"/usr/sbin/postfix", "real postfix binary", "9.9", MatchOtherVersion},
		{"/usr/sbin/postfix", "proxy to the kali", "", Mismatch},
		{"/usr/sbin/nologin", "#!/bin/sh\nbash -i", "", Mismatch},
		{"/usr/local/bin/mystery", "whatever", "", Unknown},
		{"/tmp/x", "sliver implant", "", KnownBad},
		{"/tmp/copy-of-su", "su binary", "", Unknown},
	}
	for _, c := range cases {
		r := l.Judge(c.path, sumOf(c.content), c.claimed)
		if r.Verdict != c.want {
			t.Errorf("%s %q: got %s want %s", c.path, c.content, r.Verdict, c.want)
		}
	}
	r := l.Judge("/usr/sbin/postfix", sumOf("proxy"), "")
	if len(r.Expected) != 1 || r.Expected[0].SHA256 != sumOf("real postfix binary") || r.Expected[0].Source != SourceVendorPackage {
		t.Fatalf("mismatch lacks expected evidence: %+v", r)
	}
	if r := l.Judge("/tmp/copy-of-su", sumOf("su binary"), ""); len(r.HashKnownAt) != 1 || r.HashKnownAt[0] != "/usr/bin/su" {
		t.Fatalf("HashKnownAt: %+v", r)
	}
}

func TestHostHintNeverProves(t *testing.T) {
	l := NewLedger(Meta{})
	l.Add(Entry{Path: "/usr/bin/evil", SHA256: sumOf("evil"), Package: "p", Source: SourceHostHint})
	r := l.Judge("/usr/bin/evil", sumOf("evil"), "")
	if r.Verdict != Unknown || !r.HintOnly {
		t.Fatalf("host hint must not prove: %+v", r)
	}
}

func TestMarshalRoundTripSignedAndTamper(t *testing.T) {
	l := buildTestLedger(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, err := l.Marshal(Ed25519Signer{priv})
	if err != nil {
		t.Fatal(err)
	}
	l2, err := Unmarshal(data, Ed25519Verifier{pub})
	if err != nil {
		t.Fatal(err)
	}
	if l2.Len() != l.Len() || l2.Meta != l.Meta {
		t.Fatalf("round trip lost data: %d vs %d", l2.Len(), l.Len())
	}
	a, b := l.Entries(), l2.Entries()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("entry %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
	if _, ok := l2.Bad(sumOf("sliver implant")); !ok {
		t.Fatal("bad list lost")
	}
	// Any flipped bit must be rejected.
	for _, off := range []int{len(magic) + 3, len(data) - 5, len(data) / 2} {
		bad := append([]byte(nil), data...)
		bad[off] ^= 0x40
		if _, err := Unmarshal(bad, Ed25519Verifier{pub}); err == nil {
			t.Fatalf("tamper at %d accepted", off)
		}
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Unmarshal(data, Ed25519Verifier{otherPub}); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Compactness: sorted/front-coded/zstd beats the naive size.
	if len(data) > l.Len()*(32+60) {
		t.Fatalf("ledger not compact: %d bytes for %d entries", len(data), l.Len())
	}
}

func TestWinbindexImport(t *testing.T) {
	js := `{
	 "` + sumOf("dns v1").String() + `": {"fileInfo": {"size": 5, "sha256": "` + sumOf("dns v1").String() + `", "version": "10.0.17763.1 (WinBuild)", "signingStatus": "Signed"}},
	 "` + sumOf("dns v2").String() + `": {"fileInfo": {"size": 6, "sha256": "` + sumOf("dns v2").String() + `", "version": "10.0.17763.2", "signingStatus": "Unsigned"}},
	 "nothex": {"fileInfo": {}}
	}`
	for name, in := range map[string][]byte{"plain": []byte(js), "gzip": compressAs(t, "gz", []byte(js))} {
		es, err := ImportWinbindex(strings.NewReader(string(in)), "DNS.exe", WinbindexOptions{OS: "win2019", Dirs: []string{`C:\Windows\System32`, `C:\Windows\SysWOW64\`}})
		if err != nil {
			t.Fatal(name, err)
		}
		if len(es) != 4 {
			t.Fatalf("%s: %d entries", name, len(es))
		}
		l := NewLedger(Meta{})
		l.AddAll(es)
		r := l.Judge(`C:\Windows\System32\dns.EXE`, sumOf("dns v1"), "")
		if r.Verdict != Match || r.Matched.Signer != "Microsoft Windows" || r.Matched.Version != "10.0.17763.1 (WinBuild)" {
			t.Fatalf("%s: %+v", name, r)
		}
		if r := l.Judge(`C:\Windows\System32\dns.exe`, sumOf("kill switch build"), ""); r.Verdict != Mismatch {
			t.Fatalf("%s: replaced dns.exe -> %s", name, r.Verdict)
		}
		if l.ByHash(sumOf("dns v2"))[0].Signer != "" {
			t.Fatal("unsigned file got a signer")
		}
	}
}

func TestDpkgHints(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	os.MkdirAll(info, 0o755)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"),
		[]byte("Package: postfix\nStatus: install ok installed\nVersion: 3.6.4-1\nDescription: x\n y\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\n"), 0o644)
	os.WriteFile(filepath.Join(info, "postfix.md5sums"), []byte("d41d8cd98f00b204e9800998ecf8427e  usr/sbin/postfix\n"), 0o644)
	h, err := ReadDpkgHints(root)
	if err != nil {
		t.Fatal(err)
	}
	if h.Packages["postfix"] != "3.6.4-1" || h.Packages["gone"] != "" {
		t.Fatalf("packages: %v", h.Packages)
	}
	if h.ClaimedVersion("/usr/sbin/postfix") != "3.6.4-1" || h.Owner("/sbin/postfix") != "postfix" {
		t.Fatalf("files: %v", h.Files)
	}
}

func TestRPMDBHints(t *testing.T) {
	db := filepath.Join(t.TempDir(), "rpmdb.sqlite")
	conn, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	conn.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
	pkg := makeRPM(t, "bash", "5.1.8", "6.el9", "gz", []fxFile{{Path: "/usr/bin/bash", Data: "bash bytes", Mode: 0o755}})
	// The rpmdb blob is the main header without the 8-byte magic/reserved.
	blob := mainHeaderBlob(t, pkg)
	if _, err := conn.Exec("INSERT INTO Packages (blob) VALUES (?)", blob); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	h, err := ReadRPMDBHints(db)
	if err != nil {
		t.Fatal(err)
	}
	if h.ClaimedVersion("/usr/bin/bash") != "5.1.8-6.el9" {
		t.Fatalf("%+v", h)
	}
	es := h.Entries("rocky9")
	if len(es) != 1 || es[0].SHA256 != sumOf("bash bytes") || es[0].Source != SourceHostHint {
		t.Fatalf("entries %+v", es)
	}
}

// mainHeaderBlob extracts the main header (after lead + padded signature header).
func mainHeaderBlob(t *testing.T, rpm []byte) []byte {
	t.Helper()
	p := 96
	il := int(be32(rpm[p+8:]))
	dl := int(be32(rpm[p+12:]))
	p += 16 + il*16 + dl
	p += (8 - (il*16+dl)%8) % 8
	il = int(be32(rpm[p+8:]))
	dl = int(be32(rpm[p+12:]))
	return rpm[p+8 : p+16+il*16+dl]
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
