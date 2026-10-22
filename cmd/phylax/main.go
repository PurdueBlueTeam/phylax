// Command phylax is the single Phylax binary: the controller (serve), the host
// agent (agent), and the operator tools. See phylax_design.md.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, `usage: phylax <command> [flags]

commands:
  serve     run the controller
  agent     run the host agent
  version   print the version`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "serve", "agent":
		fmt.Fprintf(os.Stderr, "phylax %s: not implemented yet\n", os.Args[1])
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}
