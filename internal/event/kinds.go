package event

// The common kinds every producer translates to (design: "Event kinds").
const (
	KindProcessStart = "process_start"
	KindProcessExit  = "process_exit"
	KindFileChange   = "file_change"
	KindConn         = "conn"
	KindListener     = "listener"
	KindAuthEvent    = "auth_event"
	KindDNSQuery     = "dns_query"
	KindTelemetryGap = "telemetry_gap"
)

type ProcessParent struct {
	PID        int    `json:"pid,omitempty"`
	Exe        string `json:"exe,omitempty"`
	Comm       string `json:"comm,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	Service    string `json:"service,omitempty"`
	StartTicks uint64 `json:"start_ticks,omitempty"`
	Live       bool   `json:"live,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
}

type ProcessStart struct {
	PID        int               `json:"pid"`
	PPID       int               `json:"ppid,omitempty"`
	Exe        string            `json:"exe"`
	Comm       string            `json:"comm,omitempty"`
	Cmdline    string            `json:"cmdline,omitempty"`
	CWD        string            `json:"cwd,omitempty"`
	User       string            `json:"user,omitempty"`
	UID        *int              `json:"uid,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Parent     *ProcessParent    `json:"parent,omitempty"`
	Source     string            `json:"source"` // audit | winevt
	Argc       *int              `json:"argc,omitempty"`
	CGroup     string            `json:"cgroup,omitempty"`
	EUID       *int              `json:"euid,omitempty"`
	AUID       *int64            `json:"auid,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	StartTicks uint64            `json:"start_ticks,omitempty"`
	Replay     bool              `json:"replay,omitempty"`
}

type ProcessExit struct {
	ProcessStart
	ExitCode int `json:"exit_code"`
}

type FileChange struct {
	Op               string `json:"op"` // create | delete | modify | attr | rename
	Path             string `json:"path"`
	OldPath          string `json:"old_path,omitempty"`
	Exe              string `json:"exe,omitempty"`
	PID              int    `json:"pid,omitempty"`
	User             string `json:"user,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	OldSHA256        string `json:"old_sha256,omitempty"`
	ContentChanged   *bool  `json:"content_changed,omitempty"`
	IsDir            bool   `json:"is_dir,omitempty"`
	Source           string `json:"source"` // audit | sweep | winevt
	Comm             string `json:"comm,omitempty"`
	WriterCmdline    string `json:"writer_cmdline,omitempty"`
	WriterStartTicks uint64 `json:"writer_start_ticks,omitempty"`
	SelfTamper       bool   `json:"self_tamper,omitempty"`
	WriterKnown      *bool  `json:"writer_known,omitempty"`
	GPO              bool   `json:"gpo,omitempty"`
	GPOGUID          string `json:"gpo_guid,omitempty"`
	GPOSection       string `json:"gpo_section,omitempty"`
	GPOItem          string `json:"gpo_item,omitempty"`
	SysvolPolicy     bool   `json:"sysvol_policy,omitempty"`
	Replay           bool   `json:"replay,omitempty"`
}

type Conn struct {
	Op          string `json:"op"`  // opened | closed
	Dir         string `json:"dir"` // inbound | outbound
	Proto       string `json:"proto"`
	LAddr       string `json:"laddr,omitempty"`
	LPort       uint16 `json:"lport,omitempty"`
	RAddr       string `json:"raddr,omitempty"`
	RPort       uint16 `json:"rport,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Exe         string `json:"exe,omitempty"`
	Comm        string `json:"comm,omitempty"`
	User        string `json:"user,omitempty"`
	State       string `json:"state,omitempty"`
	Service     string `json:"service,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	BytesOut    uint64 `json:"bytes_out,omitempty"`
	BytesIn     uint64 `json:"bytes_in,omitempty"`
	Source      string `json:"source"` // net | audit | winevt | capture
	Baseline    bool   `json:"baseline,omitempty"`
	ExeDeleted  bool   `json:"exe_deleted,omitempty"`
	ExeSHA256   string `json:"exe_sha256,omitempty"`
	PIDStart    uint64 `json:"pid_start,omitempty"`
	Replay      bool   `json:"replay,omitempty"`
}

type Listener struct {
	Op         string `json:"op"` // added | removed
	Proto      string `json:"proto"`
	LAddr      string `json:"laddr,omitempty"`
	LPort      uint16 `json:"lport"`
	PID        int    `json:"pid,omitempty"`
	Exe        string `json:"exe,omitempty"`
	Comm       string `json:"comm,omitempty"`
	User       string `json:"user,omitempty"`
	Service    string `json:"service,omitempty"`
	Baseline   bool   `json:"baseline,omitempty"`
	Source     string `json:"source"`
	ExeDeleted bool   `json:"exe_deleted,omitempty"`
	ExeSHA256  string `json:"exe_sha256,omitempty"`
	PIDStart   uint64 `json:"pid_start,omitempty"`
}

type AuthEvent struct {
	Result         string `json:"result"` // success | fail
	Account        string `json:"account"`
	Domain         string `json:"domain,omitempty"`
	Source         string `json:"source,omitempty"` // client address
	SourcePort     uint16 `json:"source_port,omitempty"`
	Service        string `json:"service"`
	Method         string `json:"method,omitempty"`
	LogonType      int    `json:"logon_type,omitempty"`
	InvalidUser    bool   `json:"invalid_user,omitempty"`
	Host           string `json:"host,omitempty"`
	LogonTypeName  string `json:"logon_type_name,omitempty"`
	MachineAccount bool   `json:"machine_account,omitempty"`
	Status         string `json:"status,omitempty"`
	SubStatus      string `json:"sub_status,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
	Process        string `json:"process,omitempty"`
	Workstation    string `json:"workstation,omitempty"`
	SubjectAccount string `json:"subject_account,omitempty"`
	Replay         bool   `json:"replay,omitempty"`
}

type DNSQuery struct {
	Query        string `json:"query"`
	QueryResults string `json:"query_results,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Exe          string `json:"exe,omitempty"`
	User         string `json:"user,omitempty"`
	Source       string `json:"source"`
}

type TelemetryGap struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
	From   string `json:"from,omitempty"` // RFC 3339, UTC
	To     string `json:"to,omitempty"`
	Detail string `json:"detail,omitempty"`
}
