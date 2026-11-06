package conformance

import "time"

// PreContract lists registered modules not yet on the contract; only ever shrinks.
var PreContract = []string{"audit", "capture", "deception", "detect", "health", "integrity", "net", "winevt"}

// AllowedLibraries is the closed list of shared stateless libraries.
var AllowedLibraries = []string{
	"github.com/PurdueBlueTeam/phylax/internal/atomicfile",
	"github.com/PurdueBlueTeam/phylax/internal/checks/probe",
	"github.com/PurdueBlueTeam/phylax/internal/integrity/format",
	"github.com/PurdueBlueTeam/phylax/internal/inventory/fold",
	"github.com/PurdueBlueTeam/phylax/internal/parsers",
	"github.com/PurdueBlueTeam/phylax/internal/signing",
	"github.com/PurdueBlueTeam/phylax/internal/sockets",
}

// CoreImports is the core packages a module may import.
var CoreImports = []string{
	"github.com/PurdueBlueTeam/phylax/internal/actions",
	"github.com/PurdueBlueTeam/phylax/internal/agent",
	"github.com/PurdueBlueTeam/phylax/internal/deadman",
	"github.com/PurdueBlueTeam/phylax/internal/event",
	"github.com/PurdueBlueTeam/phylax/internal/link",
	"github.com/PurdueBlueTeam/phylax/internal/manifest",
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render",
	"github.com/PurdueBlueTeam/phylax/internal/module",
	"github.com/PurdueBlueTeam/phylax/internal/plan",
	"github.com/PurdueBlueTeam/phylax/internal/store",
	"github.com/PurdueBlueTeam/phylax/internal/ui",
	"github.com/PurdueBlueTeam/phylax/internal/vault",
	"github.com/PurdueBlueTeam/phylax/plans",
}

// ModulePackages maps module names to package paths (34 catalogue modules plus health).
var ModulePackages = map[string]string{
	"health": "github.com/PurdueBlueTeam/phylax/internal/agent/mods",
}

// LinkLoss is check 7's duration; 2 s under testing.Short().
var LinkLoss = 60 * time.Second
