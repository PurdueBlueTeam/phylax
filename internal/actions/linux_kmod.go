package actions

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

var moduleRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,56}$`)

type kernelModuleBlock struct{}

func (kernelModuleBlock) Spec() Spec {
	return Spec{Name: "kernel.module_block", Risk: RiskService,
		Doc: "Blacklist a kernel module (modprobe.d blacklist + install /bin/false) and unload it if loaded and unused.",
		Params: []ParamSpec{{Name: "module", Type: String, Required: true, Max: 56, Check: func(v any) error {
			if !moduleRe.MatchString(v.(string)) {
				return errors.New("invalid module name")
			}
			return nil
		}}}}
}

func modFile(p Params) string {
	return "/etc/modprobe.d/phylax-" + strings.ReplaceAll(p.Str("module"), "-", "_") + ".conf"
}
func modContent(p Params) []byte {
	m := strings.ReplaceAll(p.Str("module"), "-", "_")
	return []byte("# managed by phylax: module blocked\nblacklist " + m + "\ninstall " + m + " /bin/false\n")
}

func (kernelModuleBlock) Locks(Params) []string    { return nil }
func (kernelModuleBlock) Touches(p Params) []Touch { return []Touch{pathTouch(modFile(p), OpModify)} }

func moduleLoaded(env *Env, mod string) (bool, error) {
	b, err := os.ReadFile(env.Resolve("/proc/modules"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	mod = strings.ReplaceAll(mod, "-", "_")
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 && f[0] == mod {
			return true, nil
		}
	}
	return false, nil
}

func (k kernelModuleBlock) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	old, exists, err := readFileIfExists(env.Resolve(modFile(p)))
	if err != nil {
		return Plan{}, err
	}
	loaded, err := moduleLoaded(env, p.Str("module"))
	if err != nil {
		return Plan{}, err
	}
	same := exists && bytes.Equal(old, modContent(p))
	if same && !loaded {
		return Plan{Done: true}, nil
	}
	var parts []string
	if !same {
		parts = append(parts, "write "+modFile(p)+"\n"+renderDiff(old, modContent(p)))
	}
	if loaded {
		parts = append(parts, "unload module "+p.Str("module"))
	}
	return Plan{Diff: strings.Join(parts, "\n")}, nil
}
func (kernelModuleBlock) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(modFile(p)))
}
func (kernelModuleBlock) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	file := env.Resolve(modFile(p))
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(file, modContent(p), 0o644); err != nil {
		return nil, err
	}
	loaded, err := moduleLoaded(env, p.Str("module"))
	if err != nil || !loaded {
		return nil, err
	}
	unload := env.lx().UnloadModule
	if unload == nil {
		unload = defaultUnloadModule
	}
	if err := unload(strings.ReplaceAll(p.Str("module"), "-", "_")); err != nil {
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.ENOENT) {
			return Output{"unloaded": "false", "reason": err.Error()}, nil // blocked from loading; still resident
		}
		return nil, fmt.Errorf("unload %s: %w", p.Str("module"), err)
	}
	return Output{"unloaded": "true"}, nil
}
func (kernelModuleBlock) Verify(_ context.Context, env *Env, p Params) error {
	b, _, err := readBounded(env.Resolve(modFile(p)))
	if err != nil {
		return err
	}
	if !bytes.Equal(b, modContent(p)) {
		return errors.New("blacklist file content differs")
	}
	return nil
}
