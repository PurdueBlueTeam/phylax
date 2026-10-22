package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

func init() {
	register(command{
		name:    "manifest",
		summary: "load, lint and render the manifest (load | lint | render <host> --format nft|windows|palo|vyos)",
		run: func(_ context.Context, args []string) error {
			return runManifest(args, os.Stdout, os.Stderr)
		},
	})
}

const manifestUsage = `usage: phylax manifest <subcommand> [flags]

  load            load and validate the manifest, print a summary
  lint            run the scoring-safety and firewall lint (exit 1 on errors)
  render <name>   render a host's firewall (nft | windows) or a device's policy
                  (palo | vyos); <name> is a host, or a device for palo and vyos

flags (any position after the subcommand):
  --dir DIR       manifest directory (default $PHYLAX_MANIFEST or ./manifest)
  --team N        override the team number
  --json          machine-readable output (load, lint)
  --format F      render format: nft | windows | palo | vyos
`

var errUsage = errors.New("usage error")

// runManifest implements `phylax manifest`; out and errw are injectable for tests.
func runManifest(args []string, out, errw io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(errw, manifestUsage)
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("manifest "+sub, flag.ContinueOnError)
	fs.SetOutput(errw)
	dir := fs.String("dir", defaultManifestDir(), "manifest directory")
	team := fs.Int("team", -1, "team number override")
	asJSON := fs.Bool("json", false, "JSON output")
	format := fs.String("format", "", "render format")
	pos, err := parseInterspersed(fs, rest)
	if err != nil {
		return err
	}
	switch sub {
	case "load", "lint":
		if len(pos) != 0 {
			return fmt.Errorf("%s takes no positional arguments (got %v)", sub, pos)
		}
	case "render":
		if len(pos) != 1 {
			return fmt.Errorf("render needs exactly one host or device name (got %d arguments)", len(pos))
		}
	default:
		fmt.Fprint(errw, manifestUsage)
		return fmt.Errorf("unknown subcommand %q", sub)
	}
	var opts manifest.Options
	if *team >= 0 {
		opts.Team = team
	}
	m, err := manifest.LoadDir(*dir, opts)
	if err != nil {
		return err
	}
	switch sub {
	case "load":
		return manifestLoad(m, *dir, *asJSON, out)
	case "lint":
		return manifestLint(m, *asJSON, out)
	default:
		return manifestRender(m, pos[0], *format, out)
	}
}

func defaultManifestDir() string {
	if d := os.Getenv("PHYLAX_MANIFEST"); d != "" {
		return d
	}
	return "manifest"
}

// parseInterspersed parses flags that may appear before or after positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

type loadSummary struct {
	Dir      string   `json:"dir"`
	Team     int      `json:"team"`
	Files    []string `json:"files"`
	Hosts    int      `json:"hosts"`
	Services int      `json:"services"`
	Scored   int      `json:"scored_services"`
	Accounts int      `json:"accounts"`
	Devices  int      `json:"devices"`
	Segments int      `json:"segments"`
}

func manifestLoad(m *manifest.Manifest, dir string, asJSON bool, out io.Writer) error {
	s := loadSummary{Dir: dir, Team: m.Team, Files: m.Loaded, Hosts: len(m.Hosts), Services: len(m.Services),
		Accounts: len(m.Accounts), Devices: len(m.Devices), Segments: len(m.Topology.Segments)}
	for _, svc := range m.Services {
		if svc.Scored {
			s.Scored++
		}
	}
	if asJSON {
		return writeJSON(out, s)
	}
	fmt.Fprintf(out, "manifest %s: ok (team %d)\n", dir, s.Team)
	fmt.Fprintf(out, "  files:    %s\n", strings.Join(s.Files, ", "))
	fmt.Fprintf(out, "  segments: %d  hosts: %d  devices: %d\n", s.Segments, s.Hosts, s.Devices)
	fmt.Fprintf(out, "  services: %d (%d scored)  accounts: %d\n", s.Services, s.Scored, s.Accounts)
	return nil
}

type lintReport struct {
	Findings []manifest.Finding `json:"findings"`
	Errors   int                `json:"errors"`
	Warnings int                `json:"warnings"`
	Info     int                `json:"info"`
	OK       bool               `json:"ok"`
}

func manifestLint(m *manifest.Manifest, asJSON bool, out io.Writer) error {
	fs, err := render.LintAll(m)
	if err != nil {
		return err
	}
	rep := lintReport{Findings: fs, OK: !manifest.HasErrors(fs)}
	if rep.Findings == nil {
		rep.Findings = []manifest.Finding{}
	}
	for _, f := range fs {
		if f.Accepted {
			continue
		}
		switch f.Severity {
		case manifest.SevError:
			rep.Errors++
		case manifest.SevWarn:
			rep.Warnings++
		default:
			rep.Info++
		}
	}
	if asJSON {
		if err := writeJSON(out, rep); err != nil {
			return err
		}
	} else {
		for _, f := range fs {
			fmt.Fprintln(out, f)
		}
		fmt.Fprintf(out, "%d error(s), %d warning(s), %d info\n", rep.Errors, rep.Warnings, rep.Info)
	}
	if !rep.OK {
		return fmt.Errorf("lint failed with %d error(s)", rep.Errors)
	}
	return nil
}

func manifestRender(m *manifest.Manifest, name, format string, out io.Writer) error {
	switch format {
	case "nft", "windows":
		if _, ok := m.Hosts[name]; !ok {
			return fmt.Errorf("unknown host %q", name)
		}
		hp, err := render.BuildHostPolicy(m, name)
		if err != nil {
			return err
		}
		if format == "nft" {
			text, err := render.NFTables(hp)
			if err != nil {
				return err
			}
			_, err = io.WriteString(out, text)
			return err
		}
		wp, err := render.WindowsRules(hp)
		if err != nil {
			return err
		}
		return writeJSON(out, wp)
	case "palo":
		pi, err := render.PaloIntents(m, name)
		if err != nil {
			return err
		}
		return writeJSON(out, pi)
	case "vyos":
		vi, err := render.VyOSIntents(m, name)
		if err != nil {
			return err
		}
		return writeJSON(out, vi)
	case "":
		return errors.New("render needs --format nft|windows|palo|vyos")
	}
	return fmt.Errorf("unknown format %q (want nft, windows, palo or vyos)", format)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
