package conformance

import "time"

// PreContract lists registered modules not yet on the contract; only ever
// shrinks. The list is the factories the agent registers today; the deception
// family registers one factory per capability (decoys, honeywatch, akiascan)
// until the deception module tasks fold them behind one manifest.
var PreContract = []string{"akiascan", "audit", "capture", "decoys", "detect", "health", "honeywatch", "integrity", "net", "winevt"}

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

// ModulePackages maps module names to package paths: the 34 catalogue modules
// plus health. A module whose package is a core package (health lives in
// internal/agent) is exempt from the sibling-import check.
var ModulePackages = map[string]string{
	"ad":            "github.com/PurdueBlueTeam/phylax/internal/ad",
	"audit":         "github.com/PurdueBlueTeam/phylax/internal/audit",
	"backup":        "github.com/PurdueBlueTeam/phylax/internal/backup",
	"capture":       "github.com/PurdueBlueTeam/phylax/internal/capture",
	"chains":        "github.com/PurdueBlueTeam/phylax/internal/chains",
	"checks":        "github.com/PurdueBlueTeam/phylax/internal/checks",
	"content_guard": "github.com/PurdueBlueTeam/phylax/internal/content_guard",
	"creds":         "github.com/PurdueBlueTeam/phylax/internal/creds",
	"decoys":        "github.com/PurdueBlueTeam/phylax/internal/decoys",
	"depot":         "github.com/PurdueBlueTeam/phylax/internal/depot",
	"deps":          "github.com/PurdueBlueTeam/phylax/internal/deps",
	"detect":        "github.com/PurdueBlueTeam/phylax/internal/detect",
	"devices":       "github.com/PurdueBlueTeam/phylax/internal/devices",
	"egress":        "github.com/PurdueBlueTeam/phylax/internal/egress",
	"firewall":      "github.com/PurdueBlueTeam/phylax/internal/firewall",
	"hardening":     "github.com/PurdueBlueTeam/phylax/internal/hardening",
	"health":        "github.com/PurdueBlueTeam/phylax/internal/agent",
	"honeytokens":   "github.com/PurdueBlueTeam/phylax/internal/honeytokens",
	"hunt":          "github.com/PurdueBlueTeam/phylax/internal/hunt",
	"integrity":     "github.com/PurdueBlueTeam/phylax/internal/integrity",
	"inventory":     "github.com/PurdueBlueTeam/phylax/internal/inventory",
	"logs":          "github.com/PurdueBlueTeam/phylax/internal/logs",
	"net":           "github.com/PurdueBlueTeam/phylax/internal/net",
	"notify":        "github.com/PurdueBlueTeam/phylax/internal/notify",
	"report":        "github.com/PurdueBlueTeam/phylax/internal/report",
	"respond":       "github.com/PurdueBlueTeam/phylax/internal/respond",
	"scorer":        "github.com/PurdueBlueTeam/phylax/internal/scorer",
	"splunk":        "github.com/PurdueBlueTeam/phylax/internal/splunk",
	"suricata":      "github.com/PurdueBlueTeam/phylax/internal/suricata",
	"teamfeed":      "github.com/PurdueBlueTeam/phylax/internal/teamfeed",
	"traceback":     "github.com/PurdueBlueTeam/phylax/internal/traceback",
	"vantage":       "github.com/PurdueBlueTeam/phylax/internal/vantage",
	"vuln":          "github.com/PurdueBlueTeam/phylax/internal/vuln",
	"wazuh":         "github.com/PurdueBlueTeam/phylax/internal/wazuh",
	"winevt":        "github.com/PurdueBlueTeam/phylax/internal/winevt",
}

// LinkLoss is check 6's duration; 2 s under testing.Short().
var LinkLoss = 60 * time.Second
