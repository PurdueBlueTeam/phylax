package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/bootstrapfile"
)

func init() {
	register(command{
		name:    "set-controller",
		summary: "point a host agent at a new controller address",
		run:     runSetController,
	})
}

const setControllerUsage = "usage: phylax set-controller [-state-dir DIR] [-pin HEX] ADDRESS[,ADDRESS...]"

// runSetController rewrites the agent's bootstrap file. The agent re-reads the
// file on its next reconnect, so no restart is needed.
func runSetController(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("set-controller", flag.ContinueOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	pin := fs.String("pin", "", "controller pin (64 hex or sha256//base64); empty keeps the current one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%s", setControllerUsage)
	}
	var addrs []string
	for _, a := range strings.Split(fs.Arg(0), ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%s", setControllerUsage)
	}
	l := agent.Layout{Root: *dir}
	if err := bootstrapfile.Rewrite(l.Bootstrap(), addrs, *pin); err != nil {
		return err
	}
	fmt.Printf("controllers: %s\n", strings.Join(addrs, ", "))
	fmt.Println("the agent follows the new address on its next reconnect (within seconds)")
	return nil
}
