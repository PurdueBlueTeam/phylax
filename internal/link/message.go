package link

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

// ProtoVersion is the wire protocol major version carried in hello/welcome.
// Within a version, JSON fields may be added; receivers ignore unknown fields.
const ProtoVersion = 1

// ProtoMinor is the minor revision within ProtoVersion. Minor 1 introduced the
// typed signed envelopes of step, step_result and control (docs/protocol.md,
// "Versioning"); minor 2 added schema and tag to the event envelope. Peers
// announce theirs in hello/welcome; a controller sends steps and controls only
// to agents that announce at least MinSignedMinor.
const (
	ProtoMinor     = 2
	MinSignedMinor = 1
)

// Type is the message type byte (bit 0x40 is reserved for the compression flag).
type Type uint8

const (
	TypeHello        Type = 0x01
	TypeHeartbeat    Type = 0x02
	TypeEvents       Type = 0x03
	TypeStepResult   Type = 0x04
	TypeChunk        Type = 0x05 // both directions
	TypeChunkHave    Type = 0x06 // both directions
	TypeAck          Type = 0x10
	TypeStep         Type = 0x11
	TypeConfig       Type = 0x12
	TypeFetch        Type = 0x13
	TypeControl      Type = 0x15
	TypeRelayRequest Type = 0x16
	TypeTokenIssue   Type = 0x17
	TypeWelcome      Type = 0x18
)

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "type(0x" + strconv.FormatUint(uint64(t), 16) + ")"
}

var typeNames = map[Type]string{
	TypeHello: "hello", TypeHeartbeat: "heartbeat", TypeEvents: "events", TypeStepResult: "step_result",
	TypeChunk: "chunk", TypeChunkHave: "chunk_have", TypeAck: "ack", TypeStep: "step", TypeConfig: "config",
	TypeFetch: "fetch", TypeControl: "control", TypeRelayRequest: "relay_request", TypeTokenIssue: "token_issue",
	TypeWelcome: "welcome",
}

// Role is which end of a connection a session is; it decides which message
// types are acceptable inbound.
type Role uint8

const (
	RoleController Role = iota // receives what agents send
	RoleAgent                  // receives what the controller sends
	RoleRelay                  // receives relay requests from the controller
)

var inbound = map[Role]map[Type]bool{
	RoleController: {TypeHello: true, TypeHeartbeat: true, TypeEvents: true, TypeStepResult: true, TypeChunk: true, TypeChunkHave: true, TypeAck: true},
	RoleAgent:      {TypeWelcome: true, TypeAck: true, TypeStep: true, TypeConfig: true, TypeFetch: true, TypeChunk: true, TypeChunkHave: true, TypeControl: true},
	RoleRelay:      {TypeRelayRequest: true},
}

// Message is one typed protocol message.
type Message interface {
	MsgType() Type
	Validate() error
}

// Limits on message contents (beyond the frame cap).
const (
	maxEventsPerBatch = 5000
	maxStr            = 1024
	maxHostLen        = 253
)

var ErrInvalid = errors.New("link: invalid message")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func checkStr(name, s string, max int, required bool) error {
	if required && s == "" {
		return invalid("%s is required", name)
	}
	if len(s) > max {
		return invalid("%s too long", name)
	}
	return nil
}

// Hello opens an agent connection.
type Hello struct {
	Proto   int            `json:"proto"`
	Host    string         `json:"host"`
	Version string         `json:"version"`
	Roles   []string       `json:"roles,omitempty"`
	Caps    map[string]any `json:"caps,omitempty"`
	LastSeq uint64         `json:"last_seq"`
	Token   string         `json:"token,omitempty"` // one-time enrollment token, first contact only
	// Minor is the sender's protocol minor revision (absent = 0).
	Minor int `json:"minor,omitempty"`
	// Deadman reports the agent's dead-man journal entries that belong to a
	// plan node (pending ones and recently finished), so a controller that
	// restarted can reconcile what happened while it was away.
	Deadman []DeadmanEntry `json:"deadman,omitempty"`
}

// MaxDeadmanEntries bounds Hello.Deadman.
const MaxDeadmanEntries = 256

// DeadmanEntry is one dead-man journal entry as reported in hello.
type DeadmanEntry struct {
	ID       string `json:"id"`
	Node     string `json:"node"`  // "<plan>:<node>"
	State    string `json:"state"` // armed|confirmed|cancelled|rolled_back|rollback_failed
	Deadline int64  `json:"deadline"`
}

func (*Hello) MsgType() Type { return TypeHello }
func (m *Hello) Validate() error {
	if m.Proto < 1 {
		return invalid("hello: proto")
	}
	if err := checkStr("host", m.Host, maxHostLen, true); err != nil {
		return err
	}
	if err := checkStr("version", m.Version, 64, false); err != nil {
		return err
	}
	if len(m.Roles) > 32 || len(m.Caps) > 256 || len(m.Deadman) > MaxDeadmanEntries || m.Minor < 0 {
		return invalid("hello: too many roles/caps/dead-man entries")
	}
	for _, d := range m.Deadman {
		if err := checkStr("deadman id", d.ID, 128, true); err != nil {
			return err
		}
		if err := checkStr("deadman node", d.Node, 2*maxStr+1, false); err != nil {
			return err
		}
		if err := checkStr("deadman state", d.State, 32, true); err != nil {
			return err
		}
	}
	return checkStr("token", m.Token, 256, false)
}

// Welcome answers hello, confirming the session (and enrollment).
type Welcome struct {
	Proto    int     `json:"proto"`
	Enrolled bool    `json:"enrolled"`
	Config   *Config `json:"config,omitempty"`
	Minor    int     `json:"minor,omitempty"`
}

func (*Welcome) MsgType() Type { return TypeWelcome }
func (m *Welcome) Validate() error {
	if m.Proto < 1 {
		return invalid("welcome: proto")
	}
	if m.Config != nil {
		return m.Config.Validate()
	}
	return nil
}

// Heartbeat is sent every 5 s by agents. HostClock is the agent's clock
// reading, used only to measure display offset.
type Heartbeat struct {
	Seq        uint64                   `json:"seq"`
	HostClock  time.Time                `json:"host_clock"`
	SpoolDepth uint64                   `json:"spool_depth"`
	Congestion string                   `json:"congestion,omitempty"` // ok|warning|full|flood|recovered
	Modules    map[string]string        `json:"modules,omitempty"`
	Health     map[string]module.Health `json:"health,omitempty"`
	SafeMode   bool                     `json:"safe_mode"`
	Drops      uint64                   `json:"drops"`
}

func (*Heartbeat) MsgType() Type { return TypeHeartbeat }
func (m *Heartbeat) Validate() error {
	if m.HostClock.IsZero() {
		return invalid("heartbeat: host_clock is required")
	}
	if len(m.Modules) > 256 {
		return invalid("heartbeat: too many modules")
	}
	if len(m.Health) > 256 {
		return invalid("heartbeat: too many health entries")
	}
	for name, h := range m.Health {
		if err := checkStr("health module", name, 64, true); err != nil {
			return err
		}
		if len(h.Detail) > 1024 {
			return invalid("heartbeat: health %s detail too long", name)
		}
		if len(h.Gaps) > 32 {
			return invalid("heartbeat: health %s has too many gaps", name)
		}
		for _, g := range h.Gaps {
			if len(g.What) > 256 || len(g.Why) > 256 {
				return invalid("heartbeat: health %s gap too long", name)
			}
		}
		if len(h.Info) > 32 {
			return invalid("heartbeat: health %s has too many info entries", name)
		}
		for k, v := range h.Info {
			if len(k) > 64 || len(v) > 256 {
				return invalid("heartbeat: health %s info %q too long", name, k)
			}
		}
	}
	return checkStr("congestion", m.Congestion, 32, false)
}

// Events carries a batch of sequenced events.
type Events struct {
	Events []event.Event `json:"events"`
}

func (*Events) MsgType() Type { return TypeEvents }
func (m *Events) Validate() error {
	if len(m.Events) == 0 || len(m.Events) > maxEventsPerBatch {
		return invalid("events: batch size %d", len(m.Events))
	}
	for i := range m.Events {
		e := &m.Events[i]
		if e.Seq == 0 || e.Agent == "" || len(e.Agent) > maxHostLen || e.Kind == "" || len(e.Kind) > 128 || e.Priority > event.PriorityBulk {
			return invalid("events: malformed event %d", i)
		}
	}
	return nil
}

// StepResult reports a plan action outcome. Its fields are the typed form of
// the signed result body (internal/plan.ResultBody): Status is the signed
// outcome, and Sig is the agent's ECDSA P-256 signature over the canonical body
// (empty for the unsigned statuses `rejected`, `unknown`, `lost`, `running`).
// Detail is an optional detail object (diff, notes) whose SHA-256 is the
// signed AfterDigest.
type StepResult struct {
	V                int             `json:"v,omitempty"`
	Plan             string          `json:"plan"`
	Node             string          `json:"node"`
	Host             string          `json:"host,omitempty"`
	Epoch            uint64          `json:"epoch"`
	Seq              uint64          `json:"seq"`
	Phase            string          `json:"phase"` // check|apply|verify|rollback
	Status           string          `json:"status"`
	Error            string          `json:"error,omitempty"`
	StepDigest       string          `json:"step_digest,omitempty"`
	RollbackDataHash string          `json:"rollback_data_hash,omitempty"`
	BeforeDigest     string          `json:"before_digest,omitempty"`
	AfterDigest      string          `json:"after_digest,omitempty"`
	StartedMS        int64           `json:"started_ms,omitempty"`
	FinishedMS       int64           `json:"finished_ms,omitempty"`
	Detail           json.RawMessage `json:"detail,omitempty"`
	Sig              []byte          `json:"sig,omitempty"`
}

func (*StepResult) MsgType() Type { return TypeStepResult }
func (m *StepResult) Validate() error {
	for _, f := range []struct {
		n, v string
		max  int
	}{{"plan", m.Plan, maxStr}, {"node", m.Node, maxStr}, {"phase", m.Phase, 32}, {"status", m.Status, 32},
		{"host", m.Host, maxHostLen}, {"step_digest", m.StepDigest, 128}, {"rollback_data_hash", m.RollbackDataHash, 128},
		{"before_digest", m.BeforeDigest, 128}, {"after_digest", m.AfterDigest, 128}} {
		if err := checkStr(f.n, f.v, f.max, f.n == "plan" || f.n == "node" || f.n == "phase" || f.n == "status"); err != nil {
			return err
		}
	}
	if len(m.Sig) > 128 {
		return invalid("step_result: sig too long")
	}
	return checkStr("error", m.Error, 8192, false)
}

// Approval is the approval record carried inside a signed step.
type Approval struct {
	By   string `json:"by"`
	At   int64  `json:"at"` // unix seconds
	Note string `json:"note,omitempty"`
}

// Step is a signed plan step. Its fields are the typed form of the signed step
// body (internal/plan.StepBody) plus the per-host secrets blob and the
// signature; the link layer only carries it, verification and canonicalisation
// belong to the executor. Params is the action's parameter object.
type Step struct {
	V              int             `json:"v"`
	Plan           string          `json:"plan"`
	PlanHash       string          `json:"plan_hash"`
	Node           string          `json:"node"`
	Host           string          `json:"host"`
	Action         string          `json:"action"`
	Phase          string          `json:"phase"`
	Params         json.RawMessage `json:"params"`
	Risk           string          `json:"risk"`
	Approval       *Approval       `json:"approval,omitempty"`
	RollbackPolicy string          `json:"rollback_policy"`
	RollbackDigest string          `json:"rollback_digest,omitempty"`
	SecretsDigest  string          `json:"secrets_digest,omitempty"`
	Epoch          uint64          `json:"epoch"`
	Seq            uint64          `json:"seq"`
	NotBefore      int64           `json:"not_before"`
	NotAfter       int64           `json:"not_after"`
	DeadmanS       int             `json:"deadman,omitempty"`
	Class          string          `json:"class,omitempty"`
	ExpiresAfterS  int             `json:"expires_after_sec,omitempty"`
	Secrets        []byte          `json:"secrets,omitempty"` // this host's secrets only; covered by SecretsDigest
	Sig            []byte          `json:"sig"`
}

func (*Step) MsgType() Type { return TypeStep }
func (m *Step) Validate() error {
	for _, f := range []struct{ n, v string }{{"plan", m.Plan}, {"node", m.Node}, {"host", m.Host}, {"action", m.Action}, {"phase", m.Phase}} {
		if err := checkStr(f.n, f.v, maxStr, true); err != nil {
			return err
		}
	}
	for _, f := range []struct{ n, v string }{{"plan_hash", m.PlanHash}, {"risk", m.Risk}, {"rollback_policy", m.RollbackPolicy},
		{"rollback_digest", m.RollbackDigest}, {"secrets_digest", m.SecretsDigest}} {
		if err := checkStr(f.n, f.v, 128, false); err != nil {
			return err
		}
	}
	if len(m.Sig) == 0 || len(m.Sig) > 128 {
		return invalid("step: sig is required")
	}
	if m.Approval != nil {
		if err := checkStr("approval.by", m.Approval.By, maxStr, false); err != nil {
			return err
		}
		if err := checkStr("approval.note", m.Approval.Note, 8192, false); err != nil {
			return err
		}
	}
	return nil
}

// Config is a signed module-config / rules update.
type Config struct {
	Version uint64          `json:"version"`
	Epoch   uint64          `json:"epoch"`
	Body    json.RawMessage `json:"body"`
	Sig     string          `json:"sig"`
}

func (*Config) MsgType() Type { return TypeConfig }
func (m *Config) Validate() error {
	if len(m.Body) == 0 {
		return invalid("config: body is required")
	}
	return checkStr("sig", m.Sig, maxStr, true)
}

// Fetch asks an agent for a pcap slice, file or telemetry window.
type Fetch struct {
	ID   string          `json:"id"`
	Kind string          `json:"kind"` // pcap|file|telemetry
	Args json.RawMessage `json:"args,omitempty"`
}

func (*Fetch) MsgType() Type { return TypeFetch }
func (m *Fetch) Validate() error {
	if err := checkStr("id", m.ID, 128, true); err != nil {
		return err
	}
	return checkStr("kind", m.Kind, 32, true)
}

// Control is a signed controller command: safe mode, freeze capture, patch
// window, dead-man confirm, step status query. Its fields are the typed form of
// the signed control body (internal/plan.ControlBody) plus the signature. The
// agent refuses any control that does not verify.
type Control struct {
	V         int             `json:"v"`
	Host      string          `json:"host"`
	Kind      string          `json:"kind"`
	On        bool            `json:"on"`
	Args      json.RawMessage `json:"args,omitempty"`
	Epoch     uint64          `json:"epoch"`
	Seq       uint64          `json:"seq"`
	NotBefore int64           `json:"not_before"`
	NotAfter  int64           `json:"not_after"`
	Sig       []byte          `json:"sig"`
}

func (*Control) MsgType() Type { return TypeControl }
func (m *Control) Validate() error {
	if err := checkStr("kind", m.Kind, 64, true); err != nil {
		return err
	}
	if err := checkStr("host", m.Host, maxHostLen, true); err != nil {
		return err
	}
	if len(m.Sig) == 0 || len(m.Sig) > 128 {
		return invalid("control: sig is required")
	}
	return nil
}

// Ack acknowledges the highest contiguous event sequence stored.
type Ack struct {
	Seq uint64 `json:"seq"`
}

func (*Ack) MsgType() Type   { return TypeAck }
func (*Ack) Validate() error { return nil }

// Chunk is one piece of a content-addressed bulk transfer. SHA256 is the
// digest of the whole object.
type Chunk struct {
	SHA256 string `json:"sha256"`
	Offset uint64 `json:"offset"`
	Total  uint64 `json:"total"`
	Data   []byte `json:"data"` // base64 in JSON
}

func (*Chunk) MsgType() Type { return TypeChunk }
func (m *Chunk) Validate() error {
	if err := validDigest(m.SHA256); err != nil {
		return err
	}
	if len(m.Data) == 0 || len(m.Data) > ChunkSize {
		return invalid("chunk: data length %d", len(m.Data))
	}
	if m.Offset > m.Total || uint64(len(m.Data)) > m.Total-m.Offset {
		return invalid("chunk: range outside object")
	}
	return nil
}

// ChunkHave tells a sender which byte ranges of an object the receiver has,
// so an interrupted transfer resumes instead of restarting.
type ChunkHave struct {
	SHA256 string      `json:"sha256"`
	Ranges [][2]uint64 `json:"ranges"` // [offset, end) pairs
}

func (*ChunkHave) MsgType() Type { return TypeChunkHave }
func (m *ChunkHave) Validate() error {
	if len(m.Ranges) > 4096 {
		return invalid("chunk_have: too many ranges")
	}
	for _, r := range m.Ranges {
		if r[0] >= r[1] {
			return invalid("chunk_have: empty range")
		}
	}
	return validDigest(m.SHA256)
}

func validDigest(s string) error {
	if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
		return invalid("sha256 must be 64 hex characters")
	}
	return nil
}

// RelayRequest asks a relay to splice a device-proxy or bootstrap stream.
type RelayRequest struct {
	Target string `json:"target"` // host:port, checked against the relay's allowlist
	Class  string `json:"class"`  // device-proxy|bootstrap
	ID     string `json:"id"`
}

func (*RelayRequest) MsgType() Type { return TypeRelayRequest }
func (m *RelayRequest) Validate() error {
	if _, port, err := net.SplitHostPort(m.Target); err != nil || port == "" {
		return invalid("relay_request: target must be host:port")
	}
	if err := checkStr("class", m.Class, 32, true); err != nil {
		return err
	}
	return checkStr("id", m.ID, 128, true)
}

// TokenIssue is the one-time enrollment token for a host (TTL 10 minutes).
type TokenIssue struct {
	Host  string `json:"host"`
	Token string `json:"token"`
	TTLS  int    `json:"ttl_s"`
}

func (*TokenIssue) MsgType() Type { return TypeTokenIssue }
func (m *TokenIssue) Validate() error {
	if err := checkStr("host", m.Host, maxHostLen, true); err != nil {
		return err
	}
	if m.TTLS <= 0 || m.TTLS > 3600 {
		return invalid("token_issue: ttl_s")
	}
	return checkStr("token", m.Token, 256, true)
}

func newMessage(t Type) Message {
	switch t {
	case TypeHello:
		return new(Hello)
	case TypeWelcome:
		return new(Welcome)
	case TypeHeartbeat:
		return new(Heartbeat)
	case TypeEvents:
		return new(Events)
	case TypeStepResult:
		return new(StepResult)
	case TypeChunk:
		return new(Chunk)
	case TypeChunkHave:
		return new(ChunkHave)
	case TypeAck:
		return new(Ack)
	case TypeStep:
		return new(Step)
	case TypeConfig:
		return new(Config)
	case TypeFetch:
		return new(Fetch)
	case TypeControl:
		return new(Control)
	case TypeRelayRequest:
		return new(RelayRequest)
	case TypeTokenIssue:
		return new(TokenIssue)
	}
	return nil
}

// ErrUnknownType is returned for an unrecognised message type byte.
var ErrUnknownType = errors.New("link: unknown message type")

// Marshal validates m and returns its type and JSON body.
func Marshal(m Message) (Type, []byte, error) {
	if err := m.Validate(); err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return 0, nil, err
	}
	return m.MsgType(), b, nil
}

// Unmarshal decodes and validates a message body. Trailing data is rejected.
func Unmarshal(t Type, body []byte) (Message, error) {
	m := newMessage(t)
	if m == nil {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownType, byte(t))
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, t, err)
	}
	if dec.More() {
		return nil, invalid("%s: trailing data", t)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// compressible reports whether a message type's body is worth compressing
// (chunk data is expected to be compressed already by whoever made it).
func compressible(t Type) bool { return t != TypeChunk }
