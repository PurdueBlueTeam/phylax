package action

// Default returns the v1 action catalog (Linux implementations).
//
// Windows-only actions (reg.*, WMI/COM, Sysmon) and the device actions
// (palo.*, vyos.*) live elsewhere: device actions run in the controller's
// `phylax` process against the XML/SSH APIs, not in the agent.
func Default() *Registry {
	r := NewRegistry()

	// Files
	r.Register("file.write", func() Action { return fileWrite{} })
	r.Register("file.template", func() Action { return fileTemplate{} })
	r.Register("file.perms", func() Action { return filePerms{} })
	r.Register("file.quarantine", func() Action { return fileQuarantine{} })
	r.Register("file.restore", func() Action { return fileRestore{} })
	r.Register("file.hash", func() Action { return fileHash{} })
	r.Register("dir.snapshot", func() Action { return dirSnapshot{} })

	// Local accounts
	r.Register("user.set_password", func() Action { return userSetPassword{} })
	r.Register("user.lock", func() Action { return userLock{} })
	r.Register("user.create", func() Action { return userCreate{} })
	r.Register("user.delete", func() Action { return userDelete{} })
	r.Register("group.members", func() Action { return groupMembers{} })
	r.Register("ssh.authorized_keys", func() Action { return sshAuthorizedKeys{} })

	// Services
	r.Register("service.state", func() Action { return serviceState{} })

	// Kernel and system
	r.Register("sysctl.set", func() Action { return sysctlSet{} })
	r.Register("module.block", func() Action { return moduleBlock{} })
	r.Register("hosts.file", func() Action { return hostsFile{} })

	// Persistence cleanup
	r.Register("cron.disable", func() Action { return cronDisable{} })
	r.Register("unit.disable", func() Action { return unitDisable{} })

	// Processes
	r.Register("proc.kill_tree", func() Action { return procKillTree{} })

	// Collection
	r.Register("collect.files", func() Action { return collectFiles{} })
	r.Register("collect.inventory", func() Action { return collectInventory{} })
	r.Register("hunt.baseline_diff", func() Action { return huntBaselineDiff{} })
	r.Register("hunt.persistence", func() Action { return huntPersistence{} })

	// Agent
	r.Register("agent.replace_binary", func() Action { return agentReplaceBinary{} })
	r.Register("agent.config", func() Action { return agentConfig{} })
	r.Register("agent.set_controller", func() Action { return agentSetController{} })
	r.Register("agent.safe_mode", func() Action { return agentSafeMode{} })

	// Probe
	r.Register("health.check", func() Action { return healthCheck{} })

	// Escape hatch
	r.Register("host.exec", func() Action { return hostExec{} })

	return r
}
