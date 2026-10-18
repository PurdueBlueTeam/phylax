// Command phylax is the single Phylax binary: controller (serve), host agent,
// and operator commands (init, set-controller, version).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "agent":
		cmdAgent(os.Args[2:])
	case "init":
		cmdInit(os.Args[2:])
	case "set-controller":
		cmdSetController(os.Args[2:])
	case "version":
		fmt.Println("phylax " + version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

var version = "0.1.0-dev"

func usage() {
	fmt.Fprintln(os.Stderr, `phylax - blue-team platform (see phylax_design.md)

Usage:
  phylax serve      run the controller (event store, plans, UI)
  phylax agent      run the host agent from a bootstrap bundle
  phylax init       verify and lay down the release bundle on the controller
  phylax set-controller <addr:port>
  phylax version`)
}
