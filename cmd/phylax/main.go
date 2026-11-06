// Command phylax is the single Phylax binary: the controller (serve), the host
// agent (agent), and the operator tools. See phylax_design.md.
//
// Each subcommand lives in its own file and registers itself in init() with
// register(), so subcommands can be developed independently.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	_ "github.com/PurdueBlueTeam/phylax/internal/module/all" // registers every module package
)

var version = "dev"

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = map[string]command{}

func register(c command) {
	if _, dup := commands[c.name]; dup {
		panic("duplicate command " + c.name)
	}
	commands[c.name] = c
}

func init() {
	register(command{name: "version", summary: "print the version", run: func(context.Context, []string) error {
		fmt.Println(version)
		return nil
	}})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: phylax <command> [flags]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-12s %s\n", n, commands[n].summary)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	c, ok := commands[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "phylax %s: %v\n", c.name, err)
		os.Exit(1)
	}
}
