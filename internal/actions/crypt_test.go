package actions

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSHA512CryptVectors(t *testing.T) {
	// Test vectors from Drepper's SHA-crypt specification.
	cases := []struct{ hash, pw string }{
		{"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
		{"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.", "Hello world!"},
		{"$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0", "This is just a test"},
	}
	for _, c := range cases {
		ok, err := CheckPassword(c.hash, c.pw)
		if err != nil || !ok {
			t.Errorf("vector %q did not verify: ok=%v err=%v", c.hash[:30], ok, err)
		}
		if ok, _ := CheckPassword(c.hash, c.pw+"x"); ok {
			t.Errorf("wrong password verified for %q", c.hash[:30])
		}
	}
}

func TestSHA512CryptMatchesOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed; known-answer vectors still cover the algorithm")
	}
	for _, pw := range []string{"a", "Changeme1!", strings.Repeat("x", 63), strings.Repeat("y", 64), strings.Repeat("zZ9", 50), "pässwörd"} {
		cmd := exec.Command("openssl", "passwd", "-6", "-salt", "abcdefghijklmnop", "-stdin")
		cmd.Stdin = strings.NewReader(pw + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Skipf("openssl passwd -6 unsupported: %v", err)
		}
		want := strings.TrimSpace(string(out))
		if got := sha512Crypt([]byte(pw), []byte("abcdefghijklmnop"), 5000, false); got != want {
			t.Errorf("pw %q: got %s want %s", pw, got, want)
		}
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	h1, err := HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashPassword("s3cret")
	if h1 == h2 {
		t.Fatal("salts must differ")
	}
	if !strings.HasPrefix(h1, "$6$") || strings.Count(h1, "$") != 3 {
		t.Fatalf("shape: %s", h1)
	}
	if ok, _ := CheckPassword(h1, "s3cret"); !ok {
		t.Fatal("does not verify")
	}
	if ok, _ := CheckPassword(h1, "s3cret2"); ok {
		t.Fatal("verifies wrong password")
	}
	if _, err := CheckPassword("$1$abc$def", "x"); err == nil {
		t.Fatal("unsupported scheme accepted")
	}
}
