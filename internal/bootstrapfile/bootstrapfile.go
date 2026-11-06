// Package bootstrapfile edits an agent's bootstrap JSON without knowing every
// field. It is a leaf (standard library, internal/atomicfile and internal/link
// only), so internal/actions can use it without importing internal/agent.
package bootstrapfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Rewrite replaces the controller addresses (and the pin when pin != "") in the
// bootstrap JSON at path, keeping every other field, including fields it does
// not know. It is atomic and validates its input before touching the file.
func Rewrite(path string, controllers []string, pin string) error {
	if len(controllers) == 0 {
		return errors.New("bootstrapfile: at least one controller address is required")
	}
	addrs := make([]string, len(controllers))
	for i, a := range controllers {
		a = strings.TrimSpace(a)
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("bootstrapfile: controller address %q: %w", a, err)
		}
		addrs[i] = a
	}
	if pin != "" {
		if _, err := link.ParsePin(pin); err != nil {
			return fmt.Errorf("bootstrapfile: pin: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("bootstrapfile: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("bootstrapfile: %s: %w", path, err)
	}
	if obj == nil {
		return fmt.Errorf("bootstrapfile: %s is not a JSON object", path)
	}
	raw, err := json.Marshal(addrs)
	if err != nil {
		return err
	}
	obj["controllers"] = raw
	if pin != "" {
		raw, err := json.Marshal(pin)
		if err != nil {
			return err
		}
		obj["controller_pin"] = raw
	}
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return atomicfile.WriteFile(path, out, 0o600)
}
