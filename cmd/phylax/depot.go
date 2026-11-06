package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/depot"
	"github.com/PurdueBlueTeam/phylax/internal/depot/gotools"
	"github.com/PurdueBlueTeam/phylax/internal/integrity"
)

func init() {
	register(command{
		name:    "depot",
		summary: "trusted tool depot (keygen | pack | fetch | deploy | list | verify | run | shell)",
		run: func(ctx context.Context, args []string) error {
			return runDepot(ctx, args, os.Stdin, os.Stdout, os.Stderr)
		},
	})
	register(command{
		name:    "tools",
		summary: "built-in inspection tools that trust nothing on the host (ps | ss | ls | hash | lsof)",
		run: func(_ context.Context, args []string) error {
			return runTools(args, os.Stdout, os.Stderr)
		},
	})
}

const depotUsage = `usage: phylax depot <subcommand> [flags]

  keygen --out PREFIX            make a release key pair (PREFIX.key PEM, PREFIX.pub hex)
  pack   --spec F --src D --store S --key K
                                 hash tools, fill the store, write the signed manifest
  fetch  --store S               fetch missing tools (controller only; verified by pinned hash)
  deploy --store S --dir D       copy this platform's tools to a hidden directory (0700)
  list                           show the verified manifest for this platform
  verify                         re-hash every deployed tool; exit 1 on any problem
  run   TOOL [ARGS...]           run one tool: verified, clean environment, depot-only PATH
  shell                          verified shell with PATH = the depot only

common flags:
  --dir D     deployed depot (default $PHYLAX_DEPOT, else derived from $PHYLAX_DEPOT_SECRET)
  --pub K     release public key: hex, or a file holding hex (default $PHYLAX_RELEASE_PUB)
`

func runDepot(ctx context.Context, args []string, in io.Reader, out, errw io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(errw, depotUsage)
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("depot "+sub, flag.ContinueOnError)
	fs.SetOutput(errw)
	dir := fs.String("dir", "", "deployed depot directory")
	pub := fs.String("pub", os.Getenv("PHYLAX_RELEASE_PUB"), "release public key")
	store := fs.String("store", "", "depot store directory")
	spec := fs.String("spec", "depot/tools.json", "build spec")
	src := fs.String("src", "", "directory with built binaries")
	key := fs.String("key", "", "release private key (PEM)")
	outp := fs.String("out", "", "output prefix")
	var pos []string
	if sub == "run" {
		// flags end at the tool name; everything after belongs to the tool
		if err := fs.Parse(rest); err != nil {
			return err
		}
		pos = fs.Args()
	} else {
		var err error
		if pos, err = parseInterspersed(fs, rest); err != nil {
			return err
		}
	}
	deployDir := func() string {
		if *dir != "" {
			return *dir
		}
		if d := os.Getenv("PHYLAX_DEPOT"); d != "" {
			return d
		}
		return depot.HiddenDir("", os.Getenv("PHYLAX_DEPOT_SECRET"))
	}
	verifier := func() (integrity.Verifier, error) {
		k, err := loadPub(*pub)
		if err != nil {
			return nil, err
		}
		return integrity.Ed25519Verifier{Key: k}, nil
	}
	open := func() (*depot.Deployed, error) {
		v, err := verifier()
		if err != nil {
			return nil, err
		}
		return depot.OpenDeployed(deployDir(), v)
	}

	switch sub {
	case "keygen":
		if *outp == "" {
			return errors.New("keygen: --out PREFIX is required")
		}
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*outp+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(*outp+".pub", []byte(hex.EncodeToString(pk)+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "public key: %s\n", hex.EncodeToString(pk))
		return nil

	case "pack":
		if *store == "" || *src == "" || *key == "" {
			return errors.New("pack: --store, --src and --key are required")
		}
		sk, err := loadPriv(*key)
		if err != nil {
			return err
		}
		sp, err := depot.LoadSpec(*spec)
		if err != nil {
			return err
		}
		m, err := depot.Pack(sp, *src, depot.Store{Dir: *store}, integrity.Ed25519Signer{Key: sk}, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "packed %d tools into %s\n", len(m.Tools), *store)
		return nil

	case "fetch":
		if *store == "" {
			return errors.New("fetch: --store is required")
		}
		v, err := verifier()
		if err != nil {
			return err
		}
		st := depot.Store{Dir: *store}
		raw, err := os.ReadFile(st.ManifestPath())
		if err != nil {
			return err
		}
		m, err := depot.Parse(raw, v)
		if err != nil {
			return err
		}
		got, errs := st.FetchMissing(ctx, m, httpFetcher{}, runtime.GOOS, runtime.GOARCH)
		for _, g := range got {
			fmt.Fprintf(out, "fetched %s\n", g)
		}
		for _, e := range errs {
			fmt.Fprintf(errw, "fetch: %v\n", e)
		}
		if len(errs) > 0 {
			return fmt.Errorf("%d tools not fetched", len(errs))
		}
		return nil

	case "deploy":
		if *store == "" {
			return errors.New("deploy: --store is required")
		}
		v, err := verifier()
		if err != nil {
			return err
		}
		st := depot.Store{Dir: *store}
		raw, err := os.ReadFile(st.ManifestPath())
		if err != nil {
			return err
		}
		m, err := depot.Parse(raw, v)
		if err != nil {
			return err
		}
		d := deployDir()
		rep, err := depot.Deploy(st, m, raw, d, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "deployed %d tools to %s\n", len(rep.Deployed), d)
		if len(rep.Missing) > 0 {
			fmt.Fprintf(errw, "not in the store (run fetch): %s\n", strings.Join(rep.Missing, ", "))
		}
		return nil

	case "list":
		d, err := open()
		if err != nil {
			return err
		}
		for _, e := range d.M.For(d.GOOS, d.GOARCH) {
			ap := ""
			if len(e.Provides) > 0 {
				ap = fmt.Sprintf(" (+%d applets)", len(e.Provides))
			}
			h := e.SHA256
			if len(h) > 12 {
				h = h[:12]
			}
			fmt.Fprintf(out, "%-14s %-10s %-14s %s%s\n", e.Name, e.Version, e.License, h, ap)
		}
		return nil

	case "verify":
		d, err := open()
		if err != nil {
			return err
		}
		ps := d.Verify()
		for _, p := range ps {
			fmt.Fprintln(errw, "PROBLEM:", p)
		}
		if len(ps) > 0 {
			return fmt.Errorf("%d problems; do not trust this depot", len(ps))
		}
		fmt.Fprintf(out, "ok: %d tools verified\n", len(d.M.For(d.GOOS, d.GOARCH)))
		return nil

	case "run":
		if len(pos) == 0 {
			return errors.New("run: tool name required")
		}
		d, err := open()
		if err != nil {
			return err
		}
		code, err := d.Run(ctx, pos[0], pos[1:], nil, depot.IO{Stdin: in, Stdout: out, Stderr: errw})
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(code)
		}
		return nil

	case "shell":
		d, err := open()
		if err != nil {
			return err
		}
		code, err := d.Shell(ctx, depot.IO{Stdin: in, Stdout: out, Stderr: errw})
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(code)
		}
		return nil
	}
	fmt.Fprint(errw, depotUsage)
	return errUsage
}

func loadPub(s string) (ed25519.PublicKey, error) {
	if s == "" {
		return nil, errors.New("release public key required (--pub or $PHYLAX_RELEASE_PUB)")
	}
	if b, err := os.ReadFile(s); err == nil {
		s = string(b)
	}
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("release public key must be 32 bytes of hex")
	}
	return k, nil
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("private key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key: not ed25519")
	}
	return sk, nil
}

// httpFetcher fetches an entry's URL. It is only used by `depot fetch`, which
// runs on the controller (the cache path); agents never fetch.
type httpFetcher struct{}

func (httpFetcher) Fetch(ctx context.Context, e depot.Entry) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", e.URL, resp.Status)
	}
	return resp.Body, nil
}

const toolsUsage = `usage: phylax tools <ps|ss|ls|hash|lsof> [args]

  ps                 processes from /proc (flags deleted executables)
  ss                 TCP/UDP sockets via netlink sock_diag, joined to processes
  ls [PATH...]       directory listing with inode, owner, symlink targets; shows hidden files
  hash FILE...       sha256 of files
  lsof [PID...]      open file descriptors from /proc/<pid>/fd

These read the kernel directly and run no host program.
`

func runTools(args []string, out, errw io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(errw, toolsUsage)
		return errUsage
	}
	rest := args[1:]
	switch args[0] {
	case "ls":
		if len(rest) == 0 {
			rest = []string{"."}
		}
		var first error
		for _, p := range rest {
			fs, err := gotools.List(p)
			if err != nil {
				if first == nil {
					first = err
				}
				fmt.Fprintln(errw, err)
				continue
			}
			if len(rest) > 1 {
				fmt.Fprintf(out, "%s:\n", p)
			}
			gotools.FormatLS(out, fs)
		}
		return first
	case "hash":
		if len(rest) == 0 {
			return errors.New("hash: file required")
		}
		return gotools.Hash(out, rest)
	case "ps", "ss", "lsof":
		return runProcTool(args[0], rest, out)
	}
	fmt.Fprint(errw, toolsUsage)
	return errUsage
}
