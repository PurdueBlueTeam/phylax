package actions

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// file.plant is file.write for honey files: it can refuse to replace a file
// that exists (only_if_absent: a real .bash_history or credentials file is
// never clobbered by bait) and it can take its content from the step's secrets
// (secret_params) so the bait, which contains the honey credential, never
// appears in the plan JSON, a diff, a log line or an error.
//
// The shared file.write is left alone; plant reuses its helpers.

// plantPathParam accepts a Unix absolute path or a Windows drive path whichever
// OS validates the plan: the controller checks plans for hosts of both kinds.
var plantPathParam = ParamSpec{Name: "path", Type: String, Required: true, Max: 4096, Check: func(v any) error {
	s, _ := v.(string)
	switch {
	case strings.ContainsRune(s, 0):
		return errors.New("invalid path")
	case strings.HasPrefix(s, "/"):
		return nil
	case len(s) > 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'):
		return nil
	}
	return errors.New("path must be absolute")
}}

type filePlant struct{}

func (filePlant) Spec() Spec {
	return Spec{Name: "file.plant", Risk: RiskService,
		Doc: "Write a honey file atomically; optional only_if_absent, content from step secrets (secret_params).",
		Params: []ParamSpec{plantPathParam, modeParam, uidParam, gidParam,
			{Name: "content", Type: String, Max: maxFileBytes},
			{Name: "content_b64", Type: String, Max: maxFileBytes * 2},
			{Name: "only_if_absent", Type: Bool},
			{Name: "secret_params", Type: StringList, Max: 4},
			// secret_refs is controller-side metadata (param -> vault entry); the
			// agent never reads it.
			{Name: "secret_refs", Type: StringMap},
		}}
}

func (filePlant) Locks(p Params) []string  { return lockForPath(p.Str("path")) }
func (filePlant) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }

// content resolves the bytes to write. Errors never include the content.
func (filePlant) content(ctx context.Context, p Params) ([]byte, error) {
	names, err := secretNames(p, "content")
	if err != nil {
		return nil, err
	}
	if isSecret(names, "content") {
		if p.Has("content_b64") {
			return nil, errors.New("content is a secret parameter: content_b64 must not also be set")
		}
		v, ok := SecretParam(ctx, "content")
		if !ok {
			return nil, errors.New("secret parameter content was not delivered with the step")
		}
		return []byte(v), nil
	}
	if p.Has("content") == p.Has("content_b64") {
		return nil, errors.New("exactly one of content, content_b64 or a secret content is required")
	}
	if p.Has("content_b64") {
		return base64.StdEncoding.DecodeString(p.Str("content_b64"))
	}
	return []byte(p.Str("content")), nil
}

func (f filePlant) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	want, err := f.content(ctx, p)
	if err != nil {
		return Plan{}, err
	}
	path := env.Resolve(p.Str("path"))
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Plan{Diff: fmt.Sprintf("create %s (%d bytes, content not shown)", p.Str("path"), len(want))}, nil
	}
	if err != nil {
		return Plan{}, err
	}
	if p.Bool("only_if_absent") {
		return Plan{Done: true, Notes: []string{p.Str("path") + " exists; left untouched (only_if_absent)"}}, nil
	}
	if !st.Mode().IsRegular() {
		return Plan{}, fmt.Errorf("%s is not a regular file", p.Str("path"))
	}
	old, _, err := readBounded(path)
	if err != nil {
		return Plan{}, err
	}
	var parts []string
	if !bytes.Equal(old, want) {
		parts = append(parts, fmt.Sprintf("replace %s content (%d -> %d bytes, content not shown)", p.Str("path"), len(old), len(want)))
	}
	if m, ok := p.FileMode("mode"); ok && st.Mode().Perm() != m.Perm() {
		parts = append(parts, fmt.Sprintf("mode %04o -> %04o", st.Mode().Perm(), m.Perm()))
	}
	parts = append(parts, ownerDiff(st, p)...)
	if len(parts) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: joinLines(parts)}, nil
}

func joinLines(p []string) string {
	var b bytes.Buffer
	for i, s := range p {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s)
	}
	return b.String()
}

func (filePlant) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(p.Str("path")))
}

func (f filePlant) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	want, err := f.content(ctx, p)
	if err != nil {
		return nil, err
	}
	path := env.Resolve(p.Str("path"))
	if p.Bool("only_if_absent") { // re-check under the lock, right before the write
		if _, err := os.Lstat(path); err == nil {
			return Output{"planted": "false"}, nil
		}
	}
	perm, hasMode := p.FileMode("mode")
	if !hasMode {
		perm = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(path, want, perm.Perm()); err != nil {
		return nil, err
	}
	if hasMode {
		if err := os.Chmod(path, perm); err != nil {
			return nil, err
		}
	}
	return Output{"planted": "true"}, applyOwner(path, p)
}

func (f filePlant) Verify(ctx context.Context, env *Env, p Params) error {
	path := env.Resolve(p.Str("path"))
	if p.Bool("only_if_absent") {
		// The file may predate the plan (and then is not ours to judge).
		if _, err := os.Lstat(path); err != nil {
			return err
		}
		return nil
	}
	want, err := f.content(ctx, p)
	if err != nil {
		return err
	}
	got, st, err := readBounded(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("content differs after write")
	}
	if m, ok := p.FileMode("mode"); ok && st.Mode().Perm() != m.Perm() {
		return fmt.Errorf("mode is %04o, want %04o", st.Mode().Perm(), m.Perm())
	}
	return nil
}
