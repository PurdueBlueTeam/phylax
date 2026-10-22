package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// HostKeyFile is the SSH decoy's host key, kept in the agent state directory.
const HostKeyFile = "decoy_ssh_host_ed25519"

// LoadOrCreateHostKey returns the OpenSSH PEM of the persistent decoy host
// key, creating it (atomically, mode 0600) on first use. A decoy whose host
// key changes on every restart is a tell, and trips known_hosts warnings for
// the attacker's own tooling, so the key is generated once.
func LoadOrCreateHostKey(path string) ([]byte, error) {
	b, err := readKey(path)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(blk)
	if err := atomicfile.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("decoy host key: %w", err)
	}
	return out, nil
}

func readKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	if _, err := ssh.ParsePrivateKey(b); err != nil {
		// Never silently replace a damaged key: that would hide tampering.
		return nil, fmt.Errorf("decoy host key %s unusable: %w", path, err)
	}
	return b, nil
}

// Signer parses the PEM from LoadOrCreateHostKey.
func Signer(pemBytes []byte) (ssh.Signer, error) { return ssh.ParsePrivateKey(pemBytes) }
