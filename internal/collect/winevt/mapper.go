package winevt

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Channel names.
const (
	ChSecurity     = "Security"
	ChSystem       = "System"
	ChSysmon       = "Microsoft-Windows-Sysmon/Operational"
	ChPowerShell   = "Microsoft-Windows-PowerShell/Operational"
	ChDefender     = "Microsoft-Windows-Windows Defender/Operational"
	ChTaskSched    = "Microsoft-Windows-TaskScheduler/Operational"
	ChWMIActivity  = "Microsoft-Windows-WMI-Activity/Operational"
	providerSysmon = "Microsoft-Windows-Sysmon"
)

// Event kinds produced by the mapper. process_start, auth_success, auth_fail
// and sec_event are the names the proposed rules use (phylax-proposed-rules.md).
const (
	KindProcessStart = "process_start"
	KindProcessEnd   = "process_end"
	KindAuthSuccess  = "auth_success"
	KindAuthFail     = "auth_fail"
	KindNetConnect   = "net_connect"
	KindFileChange   = "file_change"
	KindSecEvent     = "sec_event"
)

// Mapper turns Records into events. The zero value is usable.
type Mapper struct {
	// Host overrides the Computer name from the event (optional).
	Host string
	// Use4688 reports whether Security 4688 should produce process_start.
	// Nil means yes. The module sets it to "Sysmon is not running" so the
	// fallback never duplicates Sysmon 1 (design: fallback order Sysmon, 4688).
	Use4688 func() bool
	// DropExe lists executable paths (case-insensitive, exact) whose process,
	// network and file events are dropped: the agent itself, excluded by its
	// randomised path (design: obscurity D-8).
	DropExe []string
}

func (m *Mapper) host(r *Record) string {
	if m.Host != "" {
		return m.Host
	}
	return r.Computer
}

// Map returns the normalised events for r (none when the record is
// deliberately suppressed).
func (m *Mapper) Map(r *Record) []event.Event {
	f := make(map[string]any, len(r.Data)+16)
	for k, v := range r.Data {
		f[k] = v
	}
	f["channel"] = r.Channel
	f["provider"] = r.Provider
	f["event_id"] = r.EventID
	f["record_id"] = r.RecordID
	f["host"] = m.host(r)
	if len(r.Truncated) > 0 {
		f["truncated"] = r.Truncated
	}
	e := event.Event{Time: r.Time, Kind: KindSecEvent, Priority: event.PriorityHigh, Fields: f}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	d := r.Data

	sysmon := r.Provider == providerSysmon || r.Channel == ChSysmon
	switch {
	case sysmon:
		if !m.mapSysmon(r, &e) {
			return nil
		}
	case r.Channel == ChSecurity || r.Provider == "Microsoft-Windows-Security-Auditing":
		if !m.mapSecurity(r, &e) {
			return nil
		}
	case r.Channel == ChSystem:
		mapSystem(r, &e)
	case r.Channel == ChDefender:
		mapDefender(r, &e)
	case r.Channel == ChPowerShell:
		f["category"] = "powershell"
		if r.EventID == 4104 {
			f["category"] = "script_block"
			f["script_block_text"] = d["script_block_text"]
		}
	case r.Channel == ChTaskSched:
		mapTaskSched(r, &e)
	case r.Channel == ChWMIActivity:
		if r.EventID == 5861 {
			f["category"] = "wmi_subscription"
		}
	default:
		f["category"] = "unknown"
	}
	if exe, _ := f["exe"].(string); exe != "" && m.dropExe(exe) {
		return nil
	}
	if e.Kind == KindSecEvent {
		if _, ok := f["category"]; !ok {
			f["category"] = "other"
		}
	}
	return []event.Event{e}
}

func (m *Mapper) dropExe(p string) bool {
	for _, d := range m.DropExe {
		if strings.EqualFold(d, p) {
			return true
		}
	}
	return false
}

// ---- helpers ----

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// parseNum parses "0x1a4" or decimal; ok false when not numeric.
func parseNum(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s, base = s[2:], 16
	}
	v, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

func setNum(f map[string]any, key, s string) {
	if v, ok := parseNum(s); ok {
		f[key] = v
	}
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return strings.TrimPrefix(s, "::ffff:")
}

func nonDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func qualify(domain, name string) string {
	if name == "" || name == "-" {
		return ""
	}
	if domain == "" || domain == "-" {
		return name
	}
	return domain + `\` + name
}

// parseHashes splits Sysmon "SHA1=..,MD5=..,SHA256=..,IMPHASH=.." into
// lower-case keys and lower-case hex values.
func parseHashes(s string, f map[string]any) {
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || v == "" {
			continue
		}
		f[strings.ToLower(k)] = strings.ToLower(v)
	}
}

func isTrue(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "true") }

var logonTypes = map[int]string{
	2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock",
	8: "network_cleartext", 9: "new_credentials", 10: "remote_interactive", 11: "cached_interactive",
}

// ---- Sysmon ----

func (m *Mapper) mapSysmon(r *Record, e *event.Event) bool {
	f, d := e.Fields, r.Data
	f["sensor"] = "sysmon"
	if img := d["image"]; img != "" {
		f["exe"] = img
		f["comm"] = baseName(img)
	}
	setNum(f, "pid", d["process_id"])
	if g := d["process_guid"]; g != "" {
		f["process_guid"] = g
	}
	if u := d["user"]; u != "" {
		f["user"] = u
	}
	switch r.EventID {
	case 1:
		e.Kind, e.Priority = KindProcessStart, event.PriorityNormal
		f["cmdline"] = d["command_line"]
		setNum(f, "ppid", d["parent_process_id"])
		f["pexe"] = d["parent_image"]
		f["pcomm"] = baseName(d["parent_image"])
		f["pcmdline"] = d["parent_command_line"]
		f["cwd"] = d["current_directory"]
		parseHashes(d["hashes"], f)
	case 5:
		e.Kind, e.Priority = KindProcessEnd, event.PriorityNormal
	case 2:
		f["category"] = "file_time_changed"
		f["path"] = d["target_filename"]
	case 3:
		e.Kind, e.Priority = KindNetConnect, event.PriorityNormal
		f["proto"] = strings.ToLower(d["protocol"])
		f["src_ip"], f["dst_ip"] = d["source_ip"], d["destination_ip"]
		setNum(f, "src_port", d["source_port"])
		setNum(f, "dst_port", d["destination_port"])
		f["dst_host"] = d["destination_hostname"]
		f["initiated"] = isTrue(d["initiated"])
		if f["initiated"] == true {
			f["dir"] = "out"
		} else {
			f["dir"] = "in"
		}
	case 4:
		e.Priority = event.PriorityCritical
		f["category"] = "sysmon_state"
		f["state"] = d["state"]
	case 16:
		e.Priority = event.PriorityCritical
		f["category"] = "sysmon_config"
		f["config_file"] = d["configuration"]
		f["config_hash"] = strings.ToLower(d["configuration_file_hash"])
	case 255:
		e.Priority = event.PriorityCritical
		f["category"] = "sysmon_error"
	case 6:
		f["category"] = "driver_load"
		f["path"] = d["image_loaded"]
		f["signed"] = isTrue(d["signed"])
		f["signature_status"] = d["signature_status"]
		f["exe"] = d["image_loaded"]
		parseHashes(d["hashes"], f)
	case 7:
		e.Priority = event.PriorityBulk
		f["category"] = "image_load"
		f["image_loaded"] = d["image_loaded"]
		f["signed"] = isTrue(d["signed"])
		parseHashes(d["hashes"], f)
	case 8:
		f["category"] = "remote_thread"
		f["source_exe"], f["target_exe"] = d["source_image"], d["target_image"]
	case 10:
		f["category"] = "process_access"
		f["source_exe"], f["target_exe"] = d["source_image"], d["target_image"]
		f["granted_access"] = d["granted_access"]
		f["target_lsass"] = strings.EqualFold(baseName(d["target_image"]), "lsass.exe")
	case 11:
		e.Kind, e.Priority = KindFileChange, event.PriorityNormal
		f["path"] = d["target_filename"]
		f["op"] = "create"
		f["actor_exe"], f["actor_pid"] = f["exe"], f["pid"]
	case 23, 26:
		e.Kind, e.Priority = KindFileChange, event.PriorityNormal
		f["path"] = d["target_filename"]
		f["op"] = "delete"
		f["actor_exe"], f["actor_pid"] = f["exe"], f["pid"]
	case 12, 13, 14:
		f["category"] = "registry"
		f["op"] = map[int]string{12: "create_delete", 13: "set_value", 14: "rename"}[r.EventID]
		f["registry_event_type"] = d["event_type"]
	case 17, 18:
		f["category"] = "pipe"
		f["pipe_name"] = d["pipe_name"]
	case 19, 20, 21:
		f["category"] = "wmi"
	case 22:
		e.Priority = event.PriorityBulk
		f["category"] = "dns_query"
		f["query"] = d["query_name"]
		f["query_results"] = d["query_results"]
	case 25:
		f["category"] = "process_tampering"
		f["tamper_type"] = d["type"]
	default:
		f["category"] = "sysmon_other"
	}
	return true
}

// ---- Security ----

func (m *Mapper) mapSecurity(r *Record, e *event.Event) bool {
	f, d := e.Fields, r.Data
	subject := qualify(d["subject_domain_name"], d["subject_user_name"])
	switch r.EventID {
	case 4688:
		if m.Use4688 != nil && !m.Use4688() {
			return false
		}
		e.Kind, e.Priority = KindProcessStart, event.PriorityNormal
		f["sensor"] = "4688"
		exe := d["new_process_name"]
		f["exe"], f["comm"] = exe, baseName(exe)
		f["cmdline"] = d["command_line"]
		setNum(f, "pid", d["new_process_id"])
		setNum(f, "ppid", d["process_id"]) // creator process id
		f["pexe"] = d["parent_process_name"]
		f["pcomm"] = baseName(d["parent_process_name"])
		f["user"] = subject
		f["logon_id"] = d["subject_logon_id"]
	case 4624, 4625:
		e.Kind, e.Priority = KindAuthSuccess, event.PriorityHigh
		if r.EventID == 4625 {
			e.Kind = KindAuthFail
			f["status"], f["sub_status"] = d["status"], d["sub_status"]
			f["failure_reason"] = d["failure_reason"]
		}
		acct := d["target_user_name"]
		f["account"] = acct
		f["domain"] = nonDash(d["target_domain_name"])
		f["source"] = cleanIP(d["ip_address"])
		f["source_port"] = nonDash(d["ip_port"])
		f["method"] = d["authentication_package_name"]
		f["service"] = "windows"
		f["workstation"] = nonDash(d["workstation_name"])
		f["process"] = d["process_name"]
		f["subject_account"] = subject
		if lt, ok := parseNum(d["logon_type"]); ok {
			f["logon_type"] = lt
			f["logon_type_name"] = logonTypes[lt]
		}
		f["machine_account"] = strings.HasSuffix(acct, "$")
		f["anonymous_logon"] = strings.EqualFold(acct, "ANONYMOUS LOGON")
		f["target_logon_id"] = d["target_logon_id"]
	case 4648:
		f["category"] = "explicit_credentials"
		f["account"] = d["target_user_name"]
		f["target_server"] = d["target_server_name"]
		f["source"] = cleanIP(d["ip_address"])
		f["subject_account"] = subject
	case 4697:
		f["category"] = "service_install"
		f["service_name"] = d["service_name"]
		f["image_path"] = d["service_file_name"]
		f["service_type"], f["start_type"] = d["service_type"], d["service_start_type"]
		f["service_account"] = d["service_account"]
		f["subject_account"] = subject
	case 4698, 4699, 4702:
		f["category"] = "scheduled_task"
		f["op"] = map[int]string{4698: "created", 4699: "deleted", 4702: "updated"}[r.EventID]
		f["subject_account"] = subject
		mapTaskContent(d["task_content"], f)
	case 4720, 4722, 4724, 4738, 4781:
		f["category"] = "account_change"
		f["op"] = map[int]string{4720: "created", 4722: "enabled", 4724: "password_reset", 4738: "changed", 4781: "renamed"}[r.EventID]
		f["account"] = d["target_user_name"]
		f["target_account"] = qualify(d["target_domain_name"], d["target_user_name"])
		f["subject_account"] = subject
	case 4728, 4729, 4732, 4733, 4756, 4757:
		f["category"] = "group_change"
		switch r.EventID {
		case 4728, 4732, 4756:
			f["op"] = "member_added"
		default:
			f["op"] = "member_removed"
		}
		f["group_name"] = d["target_user_name"]
		f["group_sid"] = d["target_sid"]
		f["member_name"] = d["member_name"]
		f["member_sid"] = d["member_sid"]
		f["subject_account"] = subject
	case 4741, 4742, 4739:
		f["category"] = "computer_account_change"
		f["account"] = d["target_user_name"]
		f["subject_account"] = subject
		anon := strings.EqualFold(d["subject_user_name"], "ANONYMOUS LOGON") || d["subject_user_sid"] == "S-1-5-7"
		f["anonymous_subject"] = anon
		if r.EventID == 4742 && anon {
			// D8b / Zerologon: password change of a machine account by ANONYMOUS LOGON.
			f["zerologon_signal"] = "4742_anonymous"
		}
	case 4662:
		f["category"] = "ad_access"
		f["object_type"], f["object_name"] = d["object_type"], d["object_name"]
		f["properties"] = d["properties"]
		f["access_mask"] = d["access_mask"]
		f["subject_account"] = subject
		props := strings.ToLower(d["properties"])
		f["replication_rights"] = strings.Contains(props, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") ||
			strings.Contains(props, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") ||
			strings.Contains(props, "89e95b76-444d-4c62-991a-0facbeda640c")
	case 5136, 5137, 5139, 5141:
		f["category"] = "ad_object_change"
		f["op"] = map[int]string{5136: "modified", 5137: "created", 5139: "moved", 5141: "deleted"}[r.EventID]
		f["object_dn"], f["object_class"] = d["object_dn"], d["object_class"]
		f["attribute"] = d["attribute_ldap_display_name"]
		f["attribute_value"] = d["attribute_value"]
		switch d["operation_type"] {
		case "%%14674":
			f["operation"] = "value_added"
		case "%%14675":
			f["operation"] = "value_deleted"
		}
		f["subject_account"] = subject
	case 4670:
		f["category"] = "permission_change"
		f["object_type"], f["object_name"] = d["object_type"], d["object_name"]
		f["old_sd"], f["new_sd"] = d["old_sd"], d["new_sd"]
		f["process_name"] = d["process_name"]
		f["subject_account"] = subject
	case 4719:
		f["category"] = "audit_policy_change"
		f["subject_account"] = subject
		f["subcategory"] = d["subcategory_guid"]
		f["changes"] = d["audit_policy_change"]
	case 1102:
		e.Priority = event.PriorityCritical
		f["category"] = "log_cleared"
		f["log"] = "Security"
		f["subject_account"] = qualify(d["subject_domain_name"], d["subject_user_name"])
	case 4768, 4769, 4771:
		f["category"] = "kerberos"
		f["account"] = d["target_user_name"]
		f["source"] = cleanIP(d["ip_address"])
		f["service_name"] = d["service_name"]
		f["ticket_encryption_type"] = d["ticket_encryption_type"]
		f["status"] = d["status"]
		et := strings.ToLower(d["ticket_encryption_type"])
		f["rc4_ticket"] = et == "0x17" || et == "0x18" || et == "23" || et == "24"
	case 4776:
		f["category"] = "ntlm_validation"
		f["account"] = d["target_user_name"]
		f["workstation"] = d["workstation"]
		f["status"] = d["status"]
	case 5140, 5145:
		f["category"] = "share_access"
		f["share_name"] = d["share_name"]
		f["share_path"] = d["share_local_path"]
		f["relative_target"] = d["relative_target_name"]
		f["source"] = cleanIP(d["ip_address"])
		f["subject_account"] = subject
	case 4929:
		f["category"] = "ad_replica_removed"
	case 5156, 5157:
		f["category"] = "wfp_connection"
	default:
		f["category"] = "security_other"
	}
	return true
}

// mapTaskContent extracts the first Exec action from a task definition XML.
func mapTaskContent(content string, f map[string]any) {
	if content == "" {
		return
	}
	var t struct {
		Actions struct {
			Exec []struct {
				Command   string `xml:"Command"`
				Arguments string `xml:"Arguments"`
			} `xml:"Exec"`
		} `xml:"Actions"`
		Principals struct {
			Principal struct {
				UserID string `xml:"UserId"`
				RunLvl string `xml:"RunLevel"`
			} `xml:"Principal"`
		} `xml:"Principals"`
	}
	if err := xml.Unmarshal([]byte(content), &t); err != nil {
		f["task_parse_error"] = true
		return
	}
	if len(t.Actions.Exec) > 0 {
		f["task_command"] = strings.TrimSpace(t.Actions.Exec[0].Command)
		f["task_arguments"] = strings.TrimSpace(t.Actions.Exec[0].Arguments)
	}
	f["task_run_as"] = t.Principals.Principal.UserID
}

// ---- System ----

func mapSystem(r *Record, e *event.Event) {
	f, d := e.Fields, r.Data
	switch r.EventID {
	case 7045:
		f["category"] = "service_install"
		f["service_name"] = d["service_name"]
		f["image_path"] = d["image_path"]
		f["service_type"], f["start_type"] = d["service_type"], d["start_type"]
		f["service_account"] = d["account_name"]
	case 104:
		e.Priority = event.PriorityCritical
		f["category"] = "log_cleared"
		f["log"] = d["channel"]
		f["subject_account"] = qualify(d["subject_domain_name"], d["subject_user_name"])
	case 5827, 5828, 5829, 5830, 5831:
		f["category"] = "netlogon_secure_channel"
		f["zerologon_signal"] = map[int]string{5827: "5827_denied", 5828: "5828_denied", 5829: "5829_vulnerable_allowed",
			5830: "5830_allowed_by_policy", 5831: "5831_allowed_by_policy"}[r.EventID]
		// Unnamed insertion strings; layout is [unverified] until a lab run
		// (design: verify every ID on the target builds). data_N stay available.
		f["machine_name"] = d["data_1"]
		f["domain_name"] = d["data_2"]
		e.Priority = event.PriorityCritical
		if r.EventID != 5829 {
			e.Priority = event.PriorityHigh
		}
	case 7036, 7040:
		f["category"] = "service_state"
	default:
		f["category"] = "system_other"
	}
}

// ---- Defender ----

func mapDefender(r *Record, e *event.Event) {
	f, d := e.Fields, r.Data
	switch r.EventID {
	case 1116, 1117:
		f["category"] = "defender_detection"
		f["threat_name"] = d["threat_name"]
		f["path"] = d["path"]
		f["process_name"] = d["process_name"]
		f["user"] = d["detection_user"]
		f["action"] = d["action_name"]
		if r.EventID == 1117 {
			f["category"] = "defender_action"
		}
		e.Priority = event.PriorityHigh
	case 5001, 5004, 5007, 5010, 5012:
		e.Priority = event.PriorityCritical
		f["category"] = "defender_tamper"
		f["tamper"] = map[int]string{5001: "realtime_disabled", 5004: "realtime_config_changed", 5007: "config_changed",
			5010: "scanning_disabled", 5012: "scanning_virus_disabled"}[r.EventID]
		if r.EventID == 5007 {
			nv := d["new_value"]
			f["new_value"], f["old_value"] = nv, d["old_value"]
			low := strings.ToLower(nv)
			f["defender_exclusion"] = strings.Contains(low, `\exclusions\`)
		}
	default:
		f["category"] = "defender_other"
	}
}

// ---- Task Scheduler ----

func mapTaskSched(r *Record, e *event.Event) {
	f, d := e.Fields, r.Data
	switch r.EventID {
	case 106, 140, 141:
		f["category"] = "scheduled_task"
		f["op"] = map[int]string{106: "created", 140: "updated", 141: "deleted"}[r.EventID]
		f["task_name"] = d["task_name"]
		f["task_user"] = d["user_context"]
		if f["task_user"] == "" {
			f["task_user"] = d["user_name"]
		}
	default:
		f["category"] = "task_other"
	}
}
