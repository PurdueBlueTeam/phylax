package action

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
)
func sum256(b []byte) [32]byte { return sha256.Sum256(b) }

func fullSHA(b []byte) string { s := sum256(b); return hex.EncodeToString(s[:]) }

func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// rollbackFile restores a file action's Before snapshot: base64 content, or
// "" when the file did not exist before (in which case it is removed).
func rollbackFile(path string, before []byte) error {
	if before == nil || len(before) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	content, err := base64.StdEncoding.DecodeString(string(before))
	if err != nil {
		// not base64 — treat as literal content (older snapshots)
		content = before
	}
	return writeWithReplace(path, string(content), 0)
}
