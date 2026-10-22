package chains

import (
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// ATT&CK technique assignment. Fixed rules, no learning. Ids are ATT&CK v19
// ids the rule corpus already uses; an alert's own technique list overrides
// the heuristic for the hop it seeded.

func base(p string) string {
	p = strings.ToLower(p)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".exe")
}

func techniqueExec(o traceback.Obs) string {
	exe := base(o.Exe)
	cmd := strings.ToLower(o.Cmdline)
	switch exe {
	case "sudo":
		return "T1548.003"
	case "su":
		return "T1548"
	case "sh", "bash", "dash", "zsh", "ash", "busybox":
		return "T1059.004"
	case "powershell", "pwsh":
		return "T1059.001"
	case "cmd":
		return "T1059.003"
	case "python", "python2", "python3":
		return "T1059.006"
	case "curl", "wget", "certutil", "bitsadmin", "tftp":
		return "T1105"
	case "nc", "ncat", "socat", "netcat":
		return "T1095"
	case "whoami", "id", "hostname":
		return "T1033"
	case "uname", "systeminfo":
		return "T1082"
	case "useradd", "adduser":
		return "T1136.001"
	case "passwd", "chpasswd", "usermod":
		return "T1098"
	case "crontab", "at", "schtasks":
		return "T1053"
	case "wsmprovhost":
		return "T1021.006"
	case "wmiprvse":
		return "T1047"
	case "systemctl":
		if strings.Contains(cmd, "enable") {
			return "T1543.002"
		}
	case "mimikatz", "procdump":
		return "T1003"
	}
	return "T1059"
}

func techniqueChangePath(path string) (tech string, persistence bool) {
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	switch {
	case strings.Contains(p, "authorized_keys"):
		return "T1098.004", true
	case strings.Contains(p, "/etc/cron") || strings.Contains(p, "/var/spool/cron"):
		return "T1053.003", true
	case strings.Contains(p, "/systemd/") || strings.HasSuffix(p, ".service") || strings.HasSuffix(p, ".timer"):
		return "T1543.002", true
	case strings.HasSuffix(p, "/.bashrc") || strings.HasSuffix(p, "/.profile") || strings.HasSuffix(p, "/.bash_profile") ||
		strings.HasPrefix(p, "/etc/profile"):
		return "T1546.004", true
	case strings.Contains(p, "rc.local") || strings.Contains(p, "/etc/init.d/"):
		return "T1037.004", true
	case strings.Contains(p, "ld.so.preload"):
		return "T1574.006", true
	case strings.Contains(p, "/etc/sudoers"):
		return "T1548.003", true
	case strings.HasSuffix(p, "/etc/passwd") || strings.HasSuffix(p, "/etc/shadow"):
		return "T1136.001", true
	case strings.Contains(p, "/startup/") || strings.Contains(p, "currentversion/run"):
		return "T1547.001", true
	case strings.Contains(p, "/var/www") || strings.Contains(p, "/inetpub/") || strings.Contains(p, "/htdocs") ||
		strings.HasSuffix(p, ".php") || strings.HasSuffix(p, ".jsp") || strings.HasSuffix(p, ".aspx") || strings.HasSuffix(p, ".asp"):
		return "T1505.003", false
	}
	return "T1565.001", false
}

func techniqueSec(o traceback.Obs) (tech string, persistence bool, ok bool) {
	switch o.Category {
	case "service_install":
		return "T1543.003", true, true
	case "scheduled_task":
		if o.Op == "deleted" {
			return "", false, false
		}
		return "T1053.005", true, true
	case "account_change":
		switch o.Op {
		case "created":
			return "T1136.002", true, true
		case "password_reset", "enabled", "changed":
			return "T1098", true, true
		}
	case "group_change":
		if o.Op == "member_added" {
			return "T1098", true, true
		}
	case "ad_object_change":
		return "T1098", false, true
	case "ad_access":
		if b, _ := o.Ev.Fields["replication_rights"].(bool); b {
			return "T1003.006", false, true
		}
	case "wmi_subscription":
		return "T1546.003", true, true
	}
	return "", false, false
}

// techniqueMove names the remote-service technique by service or port.
func techniqueMove(service string, port int) string {
	s := strings.ToLower(service)
	switch {
	case s == "ssh" || port == 22:
		return "T1021.004"
	case s == "rdp" || port == 3389:
		return "T1021.001"
	case s == "winrm" || port == 5985 || port == 5986:
		return "T1021.006"
	case s == "smb" || s == "cifs" || port == 445 || port == 139:
		return "T1021.002"
	case s == "wmi" || port == 135:
		return "T1047"
	}
	return "T1021"
}

func techniqueEgress(port int) string {
	switch port {
	case 53:
		return "T1071.004"
	case 80, 443, 8080, 8443:
		return "T1071.001"
	}
	return "T1041"
}

func techniqueAccess(service string, hasAccount bool, failures int) string {
	if failures >= 5 {
		return "T1110"
	}
	if hasAccount {
		return "T1078"
	}
	switch strings.ToLower(service) {
	case "http", "https", "web", "":
		return "T1190"
	}
	return "T1133"
}
