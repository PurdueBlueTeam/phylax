package report

import (
	"testing"
	"time"
)

func TestFilenameRules(t *testing.T) {
	for _, c := range []struct {
		k    Kind
		n, t int
		want string
		bad  bool
	}{
		{KindIR, 1, 7, "incident01_team07.pdf", false},
		{KindInject, 4, 13, "inject04_team13.pdf", false},
		{KindInject, 12, 1, "inject12_team01.pdf", false},
		{KindInject, 0, 1, "", true},
		{KindInject, 100, 1, "", true},
		{KindIR, 1, 0, "", true},
		{Kind("memo"), 1, 1, "", true},
	} {
		got, err := Filename(c.k, c.n, c.t)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("%v %d %d: %q %v", c.k, c.n, c.t, got, err)
		}
	}
	k, n, tm, err := ParseFilename("inject04_team13.pdf")
	if err != nil || k != KindInject || n != 4 || tm != 13 {
		t.Fatal(k, n, tm, err)
	}
	for _, bad := range []string{"Team 13 - Inject 4.pdf", "inject4_team13.pdf", "inject04_team13.PDF", "inject04_team13.pdf.exe",
		"incident00_team01.pdf", "inject04_team00.pdf", "inject04_teamPurdue.pdf", "../inject04_team13.pdf"} {
		if _, _, _, err := ParseFilename(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCentralTime(t *testing.T) {
	// 2027-03-06 is standard time, 2027-03-20 is daylight time (DST starts Mar 14).
	if got := Central(time.Date(2027, 3, 6, 15, 0, 5, 0, time.UTC)); got != "2027-03-06 09:00:05 CST (15:00:05 UTC)" {
		t.Error(got)
	}
	if got := Central(time.Date(2027, 3, 20, 15, 0, 5, 0, time.UTC)); got != "2027-03-20 10:00:05 CDT (15:00:05 UTC)" {
		t.Error(got)
	}
	if got := CentralShort(time.Date(2027, 3, 20, 15, 0, 5, 0, time.UTC)); got != "2027-03-20 10:00 CDT (US Central)" {
		t.Error(got)
	}
	if Central(time.Time{}) != "" {
		t.Error("zero time")
	}
}
