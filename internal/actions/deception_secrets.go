package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Step secrets. A plan never carries a secret value: its params name the
// secrets to use (secret_params) and where the controller finds them
// (secret_refs, a vault entry per param). At execution the controller resolves
// the refs from its vault and sends the values in the step's secrets blob (its
// SHA-256 is signed into the step). The agent puts the decoded blob in the
// action's context with WithSecrets; actions read it with SecretParam and
// never log, diff or return it.

type secretsKey struct{}

// maxSecretsBlob bounds the decoded blob.
const maxSecretsBlob = 4 << 20

// WithSecrets attaches a step's secrets blob (a JSON object of string values)
// to ctx. An empty blob returns ctx unchanged.
func WithSecrets(ctx context.Context, blob []byte) (context.Context, error) {
	if len(blob) == 0 {
		return ctx, nil
	}
	if len(blob) > maxSecretsBlob {
		return ctx, errors.New("step secrets too large")
	}
	var m map[string]string
	if err := json.Unmarshal(blob, &m); err != nil {
		return ctx, errors.New("step secrets are not a JSON object of strings")
	}
	return context.WithValue(ctx, secretsKey{}, m), nil
}

// SecretParam returns the secret value for a parameter name.
func SecretParam(ctx context.Context, name string) (string, bool) {
	m, _ := ctx.Value(secretsKey{}).(map[string]string)
	v, ok := m[name]
	return v, ok
}

// secretNames validates the secret_params list against what an action allows
// and rejects a plan that also carries the plaintext value.
func secretNames(p Params, allowed ...string) ([]string, error) {
	names := p.List("secret_params")
	sort.Strings(names)
	for i, n := range names {
		ok := false
		for _, a := range allowed {
			ok = ok || a == n
		}
		if !ok {
			return nil, fmt.Errorf("secret_params: %q is not a secret parameter of this action", n)
		}
		if i > 0 && names[i-1] == n {
			return nil, fmt.Errorf("secret_params: %q listed twice", n)
		}
		if p.Has(n) {
			return nil, fmt.Errorf("parameter %q is declared secret but the plan carries a value for it", n)
		}
	}
	return names, nil
}

func isSecret(names []string, n string) bool {
	for _, s := range names {
		if s == n {
			return true
		}
	}
	return false
}
