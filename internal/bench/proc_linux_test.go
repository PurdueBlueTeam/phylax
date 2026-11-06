//go:build linux

package bench

import "testing"

func TestParseStatCommWithSpaces(t *testing.T) {
	line := "123 (my (weird) name) S 1 2 3 4 5 6 7 8 9 10 250 150 0 0"
	if got := parseStatCPUTicks(line); got != 400 {
		t.Fatal(got)
	}
}
