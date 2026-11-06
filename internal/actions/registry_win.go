package actions

import "github.com/PurdueBlueTeam/phylax/internal/devices"

// This file registers the Windows, Active Directory, network-device and Splunk
// action family in the core catalog. The specs exist on every platform (the
// controller validates plans for Windows targets on Linux); the backends they
// need come from Env.Win and are implemented per platform.
func init() { Register(winFamily) }

func winFamily() []Action {
	return []Action{
		// Registry and Windows services
		registrySet{}, registrySet{del: true}, smb1(), winServiceConfig{}, winAudit{}, winDefender{}, defenderAudit{},
		winFirewall{}, winHotfix{}, agentOpt{},
		// Active Directory
		zerologonCheck{}, secureChannel(), rpcRange(),
		adAuditGroups{}, adAdminCount{}, adDisable{}, adResetPassword{}, adGroupRemove{}, adKrbtgt{},
		// Network devices
		paloPermittedIPs{}, paloCommit{}, paloApply{}, devSnapshot{kind: devices.PanOS}, devSnapshot{kind: devices.VyOS}, vyosApply{},
		// Splunk
		splunkREST{}, splunkPassword{}, splunkHEC{}, splunkSidecar{},
	}
}
