package pools

import (
	"strings"
	"testing"
)

func TestPoolsWellFormed(t *testing.T) {
	for _, f := range []string{"ssh_banners.txt", "mysql_versions.txt", "redis_versions.txt", "telnet_banners.txt",
		"http_panels.txt", "honey_filenames.txt", "users.txt", "svc_names.txt", "admin_names.txt", "shell_hostnames.txt"} {
		if len(Lines(f)) < 3 {
			t.Errorf("%s has fewer than 3 entries", f)
		}
	}
	for _, b := range Lines("ssh_banners.txt") {
		if !strings.HasPrefix(b, "SSH-2.0-") {
			t.Errorf("ssh banner %q", b)
		}
	}
	for _, p := range Lines("http_panels.txt") {
		if len(strings.Split(p, "|")) != 3 {
			t.Errorf("panel %q needs title|subtitle|server", p)
		}
	}
	for _, u := range append(Lines("users.txt"), Lines("svc_names.txt")...) {
		if strings.ContainsAny(u, " \t:\\/") {
			t.Errorf("name %q is not account-safe", u)
		}
	}
}

func TestFakeFilesystemReferencesExist(t *testing.T) {
	paths := map[string]bool{}
	for _, l := range Lines("fs/files.txt") {
		f := strings.Split(l, "\t")
		if len(f) < 2 || (f[1] != "d" && f[1] != "f") {
			t.Fatalf("bad fs line %q", l)
		}
		paths[f[0]] = true
		if f[1] == "f" {
			if len(f) < 3 {
				t.Errorf("file %s has no content name", f[0])
			} else if _, err := Read("fs/content/" + f[2]); err != nil {
				t.Errorf("%s: %v", f[0], err)
			}
		}
	}
	for p := range paths {
		if p == "/" {
			continue
		}
		parent := p[:strings.LastIndex(p, "/")]
		if parent == "" {
			parent = "/"
		}
		if !paths[parent] {
			t.Errorf("%s has no parent directory %s in the fake fs", p, parent)
		}
	}
	for _, l := range Lines("fs/commands.txt") {
		if !strings.Contains(l, "\t") {
			t.Errorf("command line without tab: %q", l)
		}
	}
}
