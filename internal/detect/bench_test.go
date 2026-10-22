package detect

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// benchEvents is a realistic mix: mostly benign exec, file, net and Windows events.
func benchEvents() []event.Event {
	mk := func(kind string, f map[string]any) event.Event {
		return event.Event{Agent: "a1", Kind: kind, Fields: f}
	}
	return []event.Event{
		mk("process_start", map[string]any{"comm": "ls", "image": "/usr/bin/ls", "cmdline": "ls -la /var/www/html", "uid": 1000, "argc": 3, "cgroup": "/user.slice/session-3.scope", "pexe": "/bin/bash", "pcomm": "bash"}),
		mk("process_start", map[string]any{"comm": "php-fpm8.1", "image": "/usr/sbin/php-fpm8.1", "cmdline": "php-fpm: pool www", "uid": 33, "argc": 2, "cgroup": "/system.slice/php8.1-fpm.service", "pcomm": "php-fpm8.1"}),
		mk("process_start", map[string]any{"comm": "systemctl", "image": "/usr/bin/systemctl", "cmdline": "systemctl status apache2", "uid": 0, "cgroup": "/user.slice", "pcomm": "bash"}),
		mk("file_change", map[string]any{"path": "/var/log/syslog", "op": "modify", "exe": "/usr/sbin/rsyslogd", "comm": "rsyslogd"}),
		mk("file_change", map[string]any{"path": "/var/www/html/cache/a.tmp", "op": "create", "exe": "/usr/sbin/php-fpm8.1"}),
		mk("file_change", map[string]any{"path": "/etc/ssh/sshd_config", "op": "modify", "exe": "/usr/bin/vim"}),
		mk("net.connection_opened", map[string]any{"dir": "inbound", "state": "established", "proto": "tcp", "raddr": "10.0.0.5", "rport": 40000, "lport": 443, "comm": "nginx", "exe": "/usr/sbin/nginx", "service": "https"}),
		mk("net.connection_opened", map[string]any{"dir": "outbound", "state": "established", "proto": "tcp", "raddr": "10.0.0.53", "rport": 53, "comm": "named", "exe": "/usr/sbin/named"}),
		mk("auth_success", map[string]any{"account": "scoring", "source": "10.8.8.8", "service": "sshd"}),
		mk("sec_event", map[string]any{"channel": "Security", "event_id": 4624, "category": "other"}),
		mk("process_start", map[string]any{"comm": "svchost.exe", "exe": `C:\Windows\System32\svchost.exe`, "cmdline": `svchost.exe -k netsvcs`, "pcomm": "services.exe"}),
		mk("sec_event", map[string]any{"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 13, "category": "registry", "target_object": `HKLM\Software\Foo\Bar`}),
	}
}

func BenchmarkCorpusPerEvent(b *testing.B) {
	rs, err := LoadDir(rulesDir, LoadOptions{})
	if err != nil {
		b.Fatal(err)
	}
	e := NewEngine(rs, Options{})
	evs := benchEvents()
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := evs[i%len(evs)]
		ev.Time = now
		e.Process(ev)
	}
	b.ReportMetric(float64(len(rs.Rules)), "rules")
}

func BenchmarkCorpusLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := LoadDir(rulesDir, LoadOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
