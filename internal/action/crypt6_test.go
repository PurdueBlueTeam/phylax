package action

import "testing"

// Vectors generated with glibc crypt(3) on this host (x86_64, -lcrypt).
func TestCrypt6Vectors(t *testing.T) {
	cases := []struct {
		pass, salt string
		rounds     int
		want       string
	}{
		{
			"test-password", "ab", 1000,
			"$6$rounds=1000$ab$iuXWDi7CpDc9GsieZPtV5B/ZfYZWP6ttkcaW3yoeU9sAdd.3L3Fx27xAd5Xg5HUtq1d7euQRvg7f/pB2/KbYo/",
		},
		{
			"Hello world! 1234", "saltstring", 0,
			"$6$saltstring$NhD0nXHl.Ju7n96sRvjiVVRnLh.TUcUTLgxWaESDPtM6StD4TQgWeflcxFBGpBpqfJbMk12c5mKVQv8kVbJii.",
		},
		{
			"a", "0123456789abcdef", 100000,
			"$6$rounds=100000$0123456789abcdef$yK7lj6VtmJdUZ7ZTEzeRSDIWwQ8M5JZ4N12O1NPMxM4QYXjUxIvAI1HVznJF1hZdDFii7GN.QTlXJwQua3d3z/",
		},
	}
	for _, tc := range cases {
		got, err := crypt6(tc.pass, tc.salt, tc.rounds)
		if err != nil {
			t.Fatalf("crypt6(%q): %v", tc.pass, err)
		}
		if got != tc.want {
			t.Errorf("crypt6(%q, %q, %d) =\n %s\nwant\n %s", tc.pass, tc.salt, tc.rounds, got, tc.want)
		}
	}
}

func TestVerifyCrypt6(t *testing.T) {
	stored, err := crypt6("s3cret!", "abcdef0123456789", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyCrypt6("s3cret!", stored) {
		t.Error("correct password rejected")
	}
	if verifyCrypt6("wrong", stored) {
		t.Error("wrong password accepted")
	}
	if verifyCrypt6("s3cret!", "not-a-hash") {
		t.Error("malformed stored hash accepted")
	}
}
