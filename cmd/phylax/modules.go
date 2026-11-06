package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/module/conformance"
)

func init() {
	register(command{name: "modules", summary: "list every module and its manifest", run: func(_ context.Context, args []string) error {
		return runModules(args, os.Stdout)
	}})
}

// moduleInfo is one registered module: its manifest (zero for a module not yet
// on the contract) and whether it is on the contract.
type moduleInfo struct {
	Name     string          `json:"name"`
	Sides    []module.Side   `json:"sides"`
	OS       []string        `json:"os,omitempty"`
	Default  bool            `json:"default"`
	Emits    int             `json:"emits"`
	Status   string          `json:"status"` // contract | pre-contract
	Manifest module.Manifest `json:"manifest"`
}

// runModules prints the module registry: one line per module, or the manifests
// as JSON.
func runModules(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("modules", flag.ContinueOnError)
	fs.SetOutput(out)
	asJSON := fs.Bool("json", false, "print the manifests as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("modules: unexpected argument %q", fs.Arg(0))
	}
	list := moduleList()
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, m := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%d\t%s\n", m.Name, sideList(m.Sides), osList(m.OS), m.Default, m.Emits, m.Status)
	}
	return w.Flush()
}

// moduleList merges both registries (agent factories and controller modules)
// into one sorted list.
func moduleList() []moduleInfo {
	pre := make(map[string]bool, len(conformance.PreContract))
	for _, n := range conformance.PreContract {
		pre[n] = true
	}
	byName := map[string]moduleInfo{}
	for _, f := range agent.Registered() {
		byName[f.Name] = newModuleInfo(f.Name, f.Manifest, pre)
	}
	for _, m := range module.Registered() {
		man := m.Manifest()
		byName[man.Name] = newModuleInfo(man.Name, man, pre)
	}
	list := make([]moduleInfo, 0, len(byName))
	for _, m := range byName {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func newModuleInfo(name string, man module.Manifest, pre map[string]bool) moduleInfo {
	status := "contract"
	if pre[name] || man.Name == "" {
		status = "pre-contract"
	}
	return moduleInfo{Name: name, Sides: man.Sides, OS: man.OS, Default: man.Default,
		Emits: len(man.Emits), Status: status, Manifest: man}
}

func sideList(sides []module.Side) string {
	if len(sides) == 0 {
		return "-"
	}
	out := make([]string, len(sides))
	for i, s := range sides {
		out[i] = string(s)
	}
	return strings.Join(out, ",")
}

func osList(oss []string) string {
	if len(oss) == 0 {
		return "-"
	}
	return strings.Join(oss, ",")
}
