package actions

// Linux and application-level actions (linux_*.go, app_*.go).
func init() {
	Register(linuxActions)
	for k, fn := range linuxUndos {
		RegisterUndo(k, fn)
	}
}

func linuxActions() []Action {
	return []Action{
		confSet{name: "ini.set", style: styleINI}, confSet{name: "conf.set"},
		xmlSet{},
		sysctlSet{}, kernelModuleBlock{}, systemdDropin{}, serviceConfig{}, cockpitDisable{},
		cronDisable{name: "cron.disable"}, cronDisable{name: "at.disable", at: true},
		fileAttr{},
		pkgAction{name: "pkg.install", op: pkgInstall}, pkgAction{name: "pkg.upgrade", op: pkgUpgrade},
		pkgAction{name: "pkg.remove", op: pkgRemove},
		firewallAllow{},
		webRemoveDir{}, webRenameDir{}, webOpenCartAudit{},
		mysqlAudit{}, mysqlLock{}, sqlQuery{},
		netTCPProbe{}, netHTTPProbe{}, commandCheck{},
		wazuhHealth{}, wazuhCapture{}, wazuhTestAlert{},
	}
}
