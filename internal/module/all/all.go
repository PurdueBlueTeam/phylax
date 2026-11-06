// Package all blank-imports every module package so the binary and the CI
// checks see one registry.
package all

import (
	_ "github.com/PurdueBlueTeam/phylax/internal/agent/mods"
	_ "github.com/PurdueBlueTeam/phylax/internal/suricata"
)
