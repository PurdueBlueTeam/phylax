package scorer

// DefaultTableVersion identifies the built-in table.
const DefaultTableVersion = "quotient-9000379/1"

// DefaultTable is the Appendix G fingerprint table: Quotient at commit
// 9000379 (Go 1.25, x/crypto v0.33.0) as measured in the lab (quotient.md
// section 6). Hash-like values change with the build run at the event: ship an
// event-specific table via ParseTable.
//
// The HTTP User-Agent is deliberately NOT a rule: it is random from hundreds of
// values and says nothing either way.
func DefaultTable() Table {
	return Table{
		Version: DefaultTableVersion,
		Source:  "quotient.md section 6 / phylax_design.md Appendix G",
		Generic: GenericWeights{Burst: 0.2, OneShot: 0.1, LearnedCred: 0.2, AdvisoryRunner: 0.03},
		Rules: []Rule{
			// SSH
			{ID: "ssh.hassh", Proto: "ssh", Layer: "ssh", Key: "ssh.hassh", Kind: MatchEq, Weight: 0.9,
				Values: []string{"a7230c16ea72e6ff36f15892c8d4d569", "0a07365cc01fa9fc82608ba4019af499"},
				Note:   "x/crypto KEXINIT: real login / BadAttempts login"},
			{ID: "ssh.pty", Proto: "ssh", Layer: "ssh", Key: "ssh.pty", Kind: MatchEq, Values: []string{"xterm 40x80"}, Weight: 0.5},
			{ID: "ssh.auth_none_password", Proto: "ssh", Layer: "ssh", Key: "ssh.auth", Kind: MatchSeqExact, Values: []string{"none", "password"}, Weight: 0.4},
			{ID: "ssh.dwell", Proto: "ssh", Layer: "ssh", Key: "ssh.dwell_ms", Kind: MatchRange, Min: 1100, Max: 1700, Weight: 0.25, Note: "Timeout/8 sleep, ~1.3s"},
			{ID: "ssh.fail_then_accept", Proto: "ssh", Layer: "ssh", Key: "ssh.fail_then_accept", Kind: MatchEq, Values: []string{"true"}, Weight: 0.4, Note: "BadAttempts"},
			// HTTP
			{ID: "http.host_port", Proto: "http", Layer: "http", Key: "http.host", Kind: MatchRegex, Pattern: `^[0-9a-fA-F.:\[\]]+:\d+$`, Weight: 0.35, Note: "Host always carries the port, even :80"},
			{ID: "http.header_set", Proto: "http", Layer: "http", Key: "http.headers", Kind: MatchExactSet,
				Values: []string{"Host", "User-Agent", "Accept-Encoding", "Connection"}, Weight: 0.6},
			{ID: "http.extra_headers", Proto: "http", Layer: "http", Key: "http.headers", Kind: MatchContains,
				Values: []string{"Accept", "Accept-Language", "Cookie", "Referer", "Upgrade-Insecure-Requests", "Cache-Control"}, Weight: 0.7, Negative: true,
				Note: "a browser or tool, not the scorer"},
			// TLS (Go ClientHello)
			{ID: "tls.ja4", Proto: "tls", Layer: "tls", Key: "tls.ja4", Kind: MatchEq, Values: []string{"t13i131000_f57a46bbacb6_ab7e3b40a677"}, Weight: 0.9, Note: "Go 1.25"},
			{ID: "tls.ja3", Proto: "tls", Layer: "tls", Key: "tls.ja3", Kind: MatchEq, Values: []string{"006598cf32b8feecd39e4337bdba9c44"}, Weight: 0.85},
			{ID: "tls.no_sni", Proto: "tls", Layer: "tls", Key: "tls.sni", Kind: MatchEq, Values: []string{""}, Weight: 0.25},
			{ID: "tls.no_alpn", Proto: "tls", Layer: "tls", Key: "tls.alpn", Kind: MatchEmptyList, Weight: 0.25},
			{ID: "tls.hello_len", Proto: "tls", Layer: "tls", Key: "tls.hello_len", Kind: MatchRange, Min: 1400, Max: 1600, Weight: 0.2},
			// DNS
			{ID: "dns.no_edns", Proto: "dns", Layer: "dns", Key: "dns.edns", Kind: MatchEq, Values: []string{"false"}, Weight: 0.2},
			{ID: "dns.rd", Proto: "dns", Layer: "dns", Key: "dns.rd", Kind: MatchEq, Values: []string{"true"}, Weight: 0.1},
			// ICMP (go-ping)
			{ID: "icmp.payload24", Proto: "icmp", Layer: "icmp", Key: "icmp.payload_len", Kind: MatchEq, Values: []string{"24"}, Weight: 0.45},
			{ID: "icmp.seq0", Proto: "icmp", Layer: "icmp", Key: "icmp.seq", Kind: MatchEq, Values: []string{"0"}, Weight: 0.15},
			// SMTP
			{ID: "smtp.cmds", Proto: "smtp", Layer: "smtp", Key: "smtp.cmds", Kind: MatchSubseq, Values: []string{"EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"}, Weight: 0.5},
			{ID: "smtp.ehlo_localhost", Proto: "smtp", Layer: "smtp", Key: "smtp.ehlo_arg", Kind: MatchEq, Values: []string{"localhost"}, Weight: 0.3},
			{ID: "smtp.8bitmime", Proto: "smtp", Layer: "smtp", Key: "smtp.mail_ext", Kind: MatchEq, Values: []string{"BODY=8BITMIME"}, Weight: 0.35},
			{ID: "smtp.subject16", Proto: "smtp", Layer: "smtp", Key: "smtp.subject", Kind: MatchRegex, Pattern: `^[0-9a-f]{16}$`, Weight: 0.7},
			{ID: "smtp.body64", Proto: "smtp", Layer: "smtp", Key: "smtp.body", Kind: MatchRegex, Pattern: `^[0-9a-f]{64}$`, Weight: 0.6},
			// IMAP / POP3 / FTP
			{ID: "imap.cmds", Proto: "imap", Layer: "imap", Key: "imap.cmds", Kind: MatchSubseq, Values: []string{"LOGIN", "LIST", "LOGOUT"}, Weight: 0.5},
			{ID: "imap.tag6", Proto: "imap", Layer: "imap", Key: "imap.tag", Kind: MatchRegex, Pattern: `^[A-Za-z0-9]{6}$`, Weight: 0.25},
			{ID: "pop3.cmds", Proto: "pop3", Layer: "pop3", Key: "pop3.cmds", Kind: MatchSubseq, Values: []string{"USER", "PASS", "NOOP", "STAT"}, Weight: 0.6},
			{ID: "ftp.cmds", Proto: "ftp", Layer: "ftp", Key: "ftp.cmds", Kind: MatchSubseq,
				Values: []string{"USER", "PASS", "FEAT", "TYPE", "OPTS", "EPSV", "RETR", "QUIT"}, Weight: 0.7},
			// SMB
			{ID: "smb.ntlm_flags", Proto: "smb", Layer: "smb", Key: "smb.ntlm_flags", Kind: MatchRange, Min: 0xe2888215, Max: 0xe2888215, Weight: 0.7},
			{ID: "smb.tree", Proto: "smb", Layer: "smb", Key: "smb.tree", Kind: MatchRegex, Pattern: `^\\\\[0-9.]+:445\\.+`, Weight: 0.5, Note: `\\ip:445\share`},
			{ID: "smb.domain_server", Proto: "smb", Layer: "smb", Key: "smb.domain_is_server", Kind: MatchEq, Values: []string{"true"}, Weight: 0.25},
			// WinRM
			{ID: "winrm.post", Proto: "winrm", Layer: "http", Key: "winrm.path", Kind: MatchEq, Values: []string{"/wsman"}, Weight: 0.35},
			{ID: "winrm.ua", Proto: "winrm", Layer: "http", Key: "winrm.ua", Kind: MatchEq, Values: []string{"Go-http-client/1.1"}, Weight: 0.4},
			{ID: "winrm.first_no_auth", Proto: "winrm", Layer: "http", Key: "winrm.first_no_auth", Kind: MatchEq, Values: []string{"true"}, Weight: 0.4},
			// Idle TCP holds (rdp, tcp checks)
			{ID: "tcp.zero_payload", Proto: "tcp", Layer: "tcp", Key: "tcp.zero_payload", Kind: MatchEq, Values: []string{"true"}, Weight: 0.3},
			{ID: "tcp.hold", Proto: "tcp", Layer: "tcp", Key: "tcp.hold_ms", Kind: MatchRange, Min: 6, Max: 100000, Weight: 0.1},
			{ID: "rdp.zero_payload", Proto: "rdp", Layer: "tcp", Key: "tcp.zero_payload", Kind: MatchEq, Values: []string{"true"}, Weight: 0.3},
			{ID: "rdp.hold", Proto: "rdp", Layer: "tcp", Key: "tcp.hold_ms", Kind: MatchRange, Min: 6, Max: 100000, Weight: 0.1},
		},
	}
}
