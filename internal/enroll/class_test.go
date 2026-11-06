package enroll

import "testing"

func TestClassNext(t *testing.T) {
	classes := []Class{ClassAuth, ClassNoShell, ClassNoSpace, ClassSELinux, ClassTimeout,
		ClassHostname, ClassWindowsSSH, ClassHostKey, ClassHashMismatch, ClassNoHeartbeat, ClassInstall}
	for _, c := range classes {
		if c.Next() == "" {
			t.Errorf("class %s has no next step", c)
		}
	}
	err := &PushError{Host: "h1", Class: ClassAuth, Detail: "password auth refused"}
	if err.Error() == "" || err.Next() == "" {
		t.Fatalf("PushError = %v", err)
	}
}
