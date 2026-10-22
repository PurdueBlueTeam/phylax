package actions

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Scoring-safety lint for configuration edits (design: Execution, "Scoring
// safety lint"; research/topics/phylax/scoring-safe-hardening.md "never do
// these" list). A refusal wraps ErrScoringUnsafe. The rules apply unless the
// guard knows this host's scored services and none of the service's names is
// among them.

// scoredInfo is implemented by guards that know the scored accounts/services.
type scoredInfo interface {
	ScoredAccounts() []string
	ServiceScored(names ...string) bool
	HasServiceList() bool
}

// ScoredAccounts lists the scored accounts of the guard.
func (g StaticGuard) ScoredAccounts() []string { return g.Accounts }

// HasServiceList reports whether the guard carries a scored-service list.
func (g StaticGuard) HasServiceList() bool { return len(g.Services) > 0 }

// ServiceScored reports whether any of names is a scored service.
func (g StaticGuard) ServiceScored(names ...string) bool {
	for _, n := range names {
		if in(g.Services, n) {
			return true
		}
	}
	return false
}

func (e *Env) scoredInfo() scoredInfo {
	switch g := e.Guard.(type) {
	case StaticGuard:
		return g
	case *StaticGuard:
		return g
	case scoredInfo:
		return g
	}
	return nil
}

// lintApplies is false only when the host's scored services are known and the
// service is not one of them.
func (e *Env) lintApplies(names ...string) bool {
	si := e.scoredInfo()
	if si == nil || !si.HasServiceList() {
		return true
	}
	return si.ServiceScored(names...)
}

func unsafeConf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrScoringUnsafe, fmt.Sprintf(format, a...))
}

func baseLower(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	return path.Base(p)
}

func lc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func isLoopbackBind(v string) bool {
	v = lc(v)
	return v == "127.0.0.1" || v == "localhost" || v == "::1" || strings.HasPrefix(v, "127.")
}

// lintConf checks one key edit on path. warnings are advisory.
func (e *Env) lintConf(p, stanza, key, value string) (warnings []string, err error) {
	lp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := baseLower(p)
	k, v := lc(key), lc(value)
	switch {
	case base == "sshd_config" || strings.Contains(lp, "/sshd_config.d/"):
		if !e.lintApplies("sshd", "ssh") {
			return nil, nil
		}
		return nil, e.lintSSHD(k, v)
	case strings.HasPrefix(base, "dovecot") || strings.Contains(lp, "/dovecot/"):
		if !e.lintApplies("dovecot") {
			return nil, nil
		}
		switch {
		case k == "disable_plaintext_auth" && (v == "yes" || v == "true"):
			return nil, unsafeConf("dovecot disable_plaintext_auth=yes: the mail checks authenticate in clear")
		case k == "ssl" && v == "required":
			return nil, unsafeConf("dovecot ssl=required breaks plain IMAP/POP3")
		case k == "auth_mechanisms" && !strings.Contains(v, "plain") && !strings.Contains(v, "login"):
			return nil, unsafeConf("dovecot auth_mechanisms must keep plain or login")
		}
	case base == "main.cf":
		if !e.lintApplies("postfix") {
			return nil, nil
		}
		return nil, lintPostfix(k, v)
	case strings.Contains(lp, "splunk"):
		if !e.lintApplies("splunk", "splunkd") {
			return nil, nil
		}
		return nil, lintSplunk(base, k, v)
	}
	if (k == "bind-address" || k == "bind_address") && isLoopbackBind(v) &&
		(strings.Contains(lp, "my.cnf") || strings.Contains(lp, "mysql") || strings.Contains(lp, "mariadb")) {
		if e.lintApplies("mysqld", "mysql", "mariadb") {
			return nil, unsafeConf("%s=%s would filter the scored database by source address", key, value)
		}
	}
	if strings.HasPrefix(base, "php") || base == "www.conf" {
		if k == "file_uploads" && (v == "off" || v == "0") {
			warnings = append(warnings, "file_uploads=Off breaks the OpenCart image manager")
		}
		if k == "disable_functions" {
			warnings = append(warnings, "disable_functions must be set in the php.ini/FPM pool the web server actually uses (check php --ini and auto_prepend_file)")
		}
	}
	return warnings, nil
}

func (e *Env) lintSSHD(k, v string) error {
	scored := []string(nil)
	if si := e.scoredInfo(); si != nil {
		scored = si.ScoredAccounts()
	}
	switch k {
	case "passwordauthentication":
		if v == "no" {
			return unsafeConf("sshd PasswordAuthentication no: the scorer logs in with a password")
		}
	case "authenticationmethods":
		hasPW := strings.Contains(v, "password") || strings.Contains(v, "keyboard-interactive")
		if !hasPW {
			return unsafeConf("sshd AuthenticationMethods %q leaves no password method for scored users", v)
		}
	case "permittty":
		if v == "no" {
			return unsafeConf("sshd PermitTTY no: the scorer requests a PTY")
		}
	case "forcecommand", "chrootdirectory":
		return unsafeConf("sshd %s breaks the scorer's interactive shell", k)
	case "logingracetime":
		if n, err := strconv.Atoi(strings.TrimRight(v, "s")); err == nil && n == 0 {
			return unsafeConf("sshd LoginGraceTime 0 lets one client hold every pre-auth slot; use 20")
		}
	case "usepam":
		if v == "no" {
			return unsafeConf("sshd UsePAM no breaks PAM password authentication on most distributions")
		}
	case "permitrootlogin":
		if v == "no" {
			for _, a := range scored {
				if strings.EqualFold(a, "root") {
					return unsafeConf("sshd PermitRootLogin no: root is a scored account")
				}
			}
		}
	case "allowusers", "denyusers", "allowgroups", "denygroups":
		if k == "allowusers" {
			fields := strings.Fields(v)
			set := map[string]bool{}
			for _, f := range fields {
				set[f] = true
			}
			if len(scored) > 0 {
				for _, a := range scored {
					if !set[strings.ToLower(a)] && !set["*"] {
						return unsafeConf("sshd AllowUsers omits scored account %q", a)
					}
				}
				return nil
			}
		}
		if k == "denyusers" {
			for _, a := range scored {
				for _, f := range strings.Fields(v) {
					if strings.EqualFold(a, f) {
						return unsafeConf("sshd DenyUsers names scored account %q", a)
					}
				}
			}
			return nil
		}
		return unsafeConf("sshd %s cannot be proven to include every scored user; use a group the plan manages", k)
	}
	return nil
}

func lintPostfix(k, v string) error {
	switch {
	case k == "smtpd_tls_security_level" && (v == "encrypt" || v == "dane-only"):
		return unsafeConf("postfix %s=%s requires TLS; the mail checks send plain", k, v)
	case k == "smtpd_tls_auth_only" && (v == "yes" || v == "true"):
		return unsafeConf("postfix smtpd_tls_auth_only=yes hides AUTH on plain port 25")
	case strings.HasPrefix(k, "smtpd_sasl") && strings.Contains(k, "security_options") && !strings.Contains(k, "tls") && strings.Contains(v, "noplaintext"):
		return unsafeConf("postfix %s noplaintext removes AUTH PLAIN/LOGIN", k)
	case strings.HasPrefix(k, "postscreen_"):
		return unsafeConf("postfix postscreen defers first contact (450); the scorer's source address rotates")
	case strings.HasSuffix(k, "_restrictions"):
		for _, bad := range []string{"reject_non_fqdn_sender", "reject_non_fqdn_recipient", "reject_unknown_sender_domain",
			"reject_unknown_recipient_domain", "reject_unverified_recipient", "reject_non_fqdn_helo_hostname"} {
			if strings.Contains(v, bad) {
				return unsafeConf("postfix %s uses %s: the scorer sends bare user names", k, bad)
			}
		}
	}
	return nil
}

func lintSplunk(base, k, v string) error {
	switch {
	case k == "enablesplunkwebssl":
		return unsafeConf("splunk enableSplunkWebSSL changes the scheme the check uses")
	case k == "mgmthostport" && isLoopbackBind(strings.Split(v, ":")[0]):
		return unsafeConf("splunk mgmtHostPort on loopback closes 8089 to the scorer")
	case k == "acceptfrom":
		return unsafeConf("splunk acceptFrom is source-address filtering of a scored service")
	case base == "authentication.conf" && (k == "lockoutattempts" || k == "lockoutusers"):
		return unsafeConf("splunk %s locks scored users after the scorer's bad-password attempts", k)
	case base == "authentication.conf" && k == "authtype" && v != "splunk":
		return unsafeConf("splunk authType %q moves scored users off native authentication", v)
	case k == "requireclientcert" && (v == "true" || v == "1"):
		return unsafeConf("splunk requireClientCert on 8089 breaks the scorer")
	}
	return nil
}
