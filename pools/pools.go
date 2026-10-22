// Package pools embeds the public decoy content pools: banners, honey file
// names and the fake-shell filesystem. The pools are public (the repo is), so
// per-host values are generated from them at deploy time and a careful attacker
// may still recognise a banner; that is accepted (design: Deception, principles).
package pools

import (
	"embed"
	"strings"
)

//go:embed *.txt fs
var files embed.FS

// Lines returns the non-empty, non-comment lines of a pool file.
func Lines(name string) []string {
	b, err := files.ReadFile(name)
	if err != nil {
		panic("pools: missing embedded pool " + name)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// Read returns an embedded file (e.g. "fs/content/passwd").
func Read(name string) ([]byte, error) { return files.ReadFile(name) }
