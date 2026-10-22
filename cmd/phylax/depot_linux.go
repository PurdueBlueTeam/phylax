//go:build linux

package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/PurdueBlueTeam/phylax/internal/depot/gotools"
)

func runProcTool(name string, args []string, out io.Writer) error {
	switch name {
	case "ps":
		gotools.FormatPS(out, gotools.PS())
	case "ss":
		rows, err := gotools.SS()
		if err != nil {
			return err
		}
		gotools.FormatSS(out, rows)
	case "lsof":
		var pids []int
		for _, a := range args {
			n, err := strconv.Atoi(a)
			if err != nil {
				return fmt.Errorf("lsof: bad pid %q", a)
			}
			pids = append(pids, n)
		}
		gotools.FormatLsof(out, gotools.Lsof(pids))
	}
	return nil
}
