package link

// Core JSON message shapes (docs/protocol.md § JSON shapes). These are the
// wire contract between agents, relays and the controller.

// Hello is the first message on an agent or relay connection.
type Hello struct {
	Host    string   `json:"host"`
	Version string   `json:"version"`
	Roles   []string `json:"roles"`
	Caps    []string `json:"caps,omitempty"`
	LastSeq uint64   `json:"last_seq"`
	Token   string   `json:"token,omitempty"` // enrollment only
}

// Heartbeat is sent by the agent every 5 s.
type Heartbeat struct {
	Seq        uint64            `json:"seq"`
	HostClock  string            `json:"host_clock"`
	SpoolDepth int               `json:"spool_depth"`
	Modules    map[string]string `json:"modules"`
	SafeMode   bool              `json:"safe_mode"`
	Drops      uint64            `json:"drops"`
}

// Event is one entry of an events batch. Data is base64 of the exact JSON
// bytes the agent spooled, so the chain hash is verbatim re-computable.
type Event struct {
	Seq  uint64 `json:"seq"`
	TS   string `json:"ts"`
	Type string `json:"type"`
	Data string `json:"data"` // base64
	Hash string `json:"hash"`
	Prev string `json:"prev"`
}

// Events is a batch of spooled events, agent to controller.
type Events struct {
	Events []Event `json:"events"`
}

// Ack tells the agent the highest contiguous sequence the controller has
// stored for it.
type Ack struct {
	Host string `json:"host"`
	Seq  uint64 `json:"seq"`
}

// Config is a signed config/rules update, controller to agent.
type Config struct {
	Host  string `json:"host"`
	Epoch int    `json:"epoch"`
	Rules []byte `json:"rules"` // signed rules blob, base64 in JSON
	Sig   string `json:"sig"`
}

// StepResult reports one plan step's phase outcome, agent to controller.
type StepResult struct {
	Plan   string `json:"plan"`
	Node   string `json:"node"`
	Epoch  int    `json:"epoch"`
	Seq    uint64 `json:"seq"`
	Phase  string `json:"phase"` // check | apply | verify | rollback
	OK     bool   `json:"ok"`
	Done   bool   `json:"done,omitempty"` // check found nothing to do
	Detail string `json:"detail,omitempty"`
	Before []byte `json:"before,omitempty"` // rollback snapshot
	After  string `json:"after,omitempty"`  // base64
}

// Step is a signed plan step, controller to agent.
type Step struct {
	Plan    string         `json:"plan"`
	Node    string         `json:"node"`
	Epoch   int            `json:"epoch"`
	Seq     uint64         `json:"seq"`
	Op      string         `json:"op"` // run | rollback
	Phase   string         `json:"phase,omitempty"` // check | apply | verify | rollback
	Action  string         `json:"action"`
	Params  map[string]any `json:"params"`
	Secrets map[string]any `json:"secrets,omitempty"` // this host only
	Before  []byte         `json:"before,omitempty"` // rollback target snapshot
	Deadman int            `json:"deadman,omitempty"` // seconds
	Sig     string         `json:"sig"` // ed25519 over plan|node|epoch|seq|op|action|params
}

// Chunk is one bulk-transfer piece (either direction).
type Chunk struct {
	SHA     string `json:"sha"`
	Offset  uint64 `json:"offset"`
	Payload string `json:"payload"` // base64
}

// Control is a controller-issued switch change.
type Control struct {
	Kind string `json:"kind"` // safe_mode | freeze | patch_window
	On   bool   `json:"on"`
}

// RelayRequest asks a relay to splice a stream to a target.
type RelayRequest struct {
	Target string `json:"target"` // addr:port
	Class  string `json:"class"`  // device_proxy | bootstrap
}
