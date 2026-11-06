package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"golang.org/x/crypto/ssh"
)

// ErrHostKeyChanged reports a host whose key differs from the first contact.
var ErrHostKeyChanged = errors.New("enroll: host key changed")

// HostKeys is known_hosts.json: the key recorded at a host's first contact,
// checked on every later contact. It is a file so the controller and the CLI
// share it.
type HostKeys struct {
	path string

	mu   sync.Mutex
	keys map[string]string // host -> authorized_keys line
}

// OpenHostKeys loads (or starts) the known-hosts file at path.
func OpenHostKeys(path string) (*HostKeys, error) {
	h := &HostKeys{path: path, keys: map[string]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &h.keys); err != nil {
			return nil, fmt.Errorf("enroll: known hosts %s: %w", path, err)
		}
	}
	return h, nil
}

// Callback returns the ssh host-key callback for host: it records the first
// key and refuses a different one later.
func (h *HostKeys) Callback(host string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		line := string(ssh.MarshalAuthorizedKey(key))
		h.mu.Lock()
		defer h.mu.Unlock()
		old, ok := h.keys[host]
		if !ok {
			h.keys[host] = line
			if err := h.saveLocked(); err != nil {
				delete(h.keys, host)
				return err
			}
			return nil
		}
		if old != line {
			return fmt.Errorf("%w for %s", ErrHostKeyChanged, host)
		}
		return nil
	}
}

func (h *HostKeys) saveLocked() error {
	b, err := json.Marshal(h.keys)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(h.path, b, 0o600)
}
