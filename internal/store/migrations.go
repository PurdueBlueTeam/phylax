package store

// migrations are applied in order; the number applied is kept in
// PRAGMA user_version. Never edit a shipped migration: append a new one.
var migrations = []string{
	// 1: core ingest tables
	`
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta(key, value) VALUES ('epoch', '1');

CREATE TABLE epochs (
  epoch    INTEGER PRIMARY KEY,
  started  INTEGER NOT NULL,           -- unix ns
  reason   TEXT NOT NULL
);
INSERT INTO epochs(epoch, started, reason) VALUES (1, 0, 'initial');

CREATE TABLE agents (
  id            TEXT PRIMARY KEY,      -- manifest host name
  pubkey        BLOB NOT NULL,         -- enrolled identity key
  enrolled_at   INTEGER NOT NULL,      -- unix ns
  last_seq      INTEGER NOT NULL DEFAULT 0,  -- ack point
  last_hash     TEXT NOT NULL DEFAULT '',    -- chain head at last_seq
  epoch         INTEGER NOT NULL DEFAULT 1,  -- epoch of the last accepted write
  restored_seq  INTEGER NOT NULL DEFAULT 0,  -- head recorded when a restore happened
  restored_hash TEXT NOT NULL DEFAULT ''
);

CREATE TABLE events (
  agent    TEXT NOT NULL REFERENCES agents(id),
  seq      INTEGER NOT NULL,
  time_ns  INTEGER NOT NULL,
  kind     TEXT NOT NULL,
  prio     INTEGER NOT NULL,
  fields   TEXT NOT NULL,              -- JSON object or 'null'
  prev     TEXT NOT NULL,
  hash     TEXT NOT NULL,
  PRIMARY KEY (agent, seq)
) WITHOUT ROWID;
CREATE INDEX events_kind_time ON events(kind, time_ns);
CREATE INDEX events_agent_kind ON events(agent, kind, seq);
CREATE INDEX events_time ON events(time_ns);

CREATE TABLE gaps (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  agent    TEXT NOT NULL REFERENCES agents(id),
  from_seq INTEGER NOT NULL,
  to_seq   INTEGER NOT NULL,
  reason   TEXT NOT NULL,
  class    TEXT NOT NULL DEFAULT '',
  count    INTEGER NOT NULL DEFAULT 0,
  time_ns  INTEGER NOT NULL
);
CREATE INDEX gaps_agent ON gaps(agent, from_seq);
`,
	// 2: tables for later milestones (design: Data model). Minimal columns;
	// no secret material anywhere, credentials hold metadata only.
	`
CREATE TABLE alerts (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  rule      TEXT NOT NULL,
  host      TEXT NOT NULL,
  severity  INTEGER NOT NULL DEFAULT 0,
  state     TEXT NOT NULL DEFAULT 'open',
  time_ns   INTEGER NOT NULL,
  keys      TEXT NOT NULL DEFAULT '{}',   -- JSON: key records
  agent     TEXT,
  seq       INTEGER,                      -- source event
  incident_id INTEGER
);
CREATE INDEX alerts_state_time ON alerts(state, time_ns);
CREATE INDEX alerts_host ON alerts(host, time_ns);

CREATE TABLE plans (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  state       TEXT NOT NULL,
  epoch       INTEGER NOT NULL,
  body        TEXT NOT NULL DEFAULT '{}',
  created_ns  INTEGER NOT NULL,
  updated_ns  INTEGER NOT NULL
);
CREATE TABLE plan_steps (
  plan_id   TEXT NOT NULL REFERENCES plans(id),
  step      TEXT NOT NULL,
  host      TEXT NOT NULL,
  action    TEXT NOT NULL,
  state     TEXT NOT NULL,
  result    TEXT NOT NULL DEFAULT '{}',
  updated_ns INTEGER NOT NULL,
  PRIMARY KEY (plan_id, step)
);

CREATE TABLE checks (
  id        TEXT PRIMARY KEY,
  service   TEXT NOT NULL,
  kind      TEXT NOT NULL,
  spec      TEXT NOT NULL DEFAULT '{}',
  state     TEXT NOT NULL DEFAULT 'active',
  updated_ns INTEGER NOT NULL
);
CREATE TABLE check_results (
  check_id  TEXT NOT NULL REFERENCES checks(id),
  time_ns   INTEGER NOT NULL,
  vantage   TEXT NOT NULL,
  ok        INTEGER NOT NULL,
  detail    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (check_id, time_ns, vantage)
) WITHOUT ROWID;

CREATE TABLE incidents (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  title      TEXT NOT NULL,
  state      TEXT NOT NULL DEFAULT 'open',
  campaign_id INTEGER,
  opened_ns  INTEGER NOT NULL,
  closed_ns  INTEGER
);
CREATE TABLE campaigns (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  name     TEXT NOT NULL,
  created_ns INTEGER NOT NULL
);
CREATE TABLE chains (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER REFERENCES campaigns(id),
  incident_id INTEGER REFERENCES incidents(id),
  confidence  REAL NOT NULL DEFAULT 0,
  created_ns  INTEGER NOT NULL
);
CREATE TABLE hops (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  chain_id  INTEGER NOT NULL REFERENCES chains(id),
  ord       INTEGER NOT NULL,
  kind      TEXT NOT NULL,
  src       TEXT NOT NULL,
  dst       TEXT NOT NULL,
  link      TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0,
  time_ns   INTEGER NOT NULL
);
CREATE INDEX hops_chain ON hops(chain_id, ord);
CREATE TABLE remediation_items (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  hop_id  INTEGER NOT NULL REFERENCES hops(id),
  action  TEXT NOT NULL,
  state   TEXT NOT NULL DEFAULT 'todo'
);

CREATE TABLE devices (
  id        TEXT PRIMARY KEY,          -- manifest name (palo, vyos, ...)
  kind      TEXT NOT NULL,
  address   TEXT NOT NULL DEFAULT '',
  state     TEXT NOT NULL DEFAULT '{}',
  updated_ns INTEGER NOT NULL
);
CREATE TABLE device_snapshots (
  device_id TEXT NOT NULL REFERENCES devices(id),
  time_ns   INTEGER NOT NULL,
  sha256    TEXT NOT NULL,
  body_ref  TEXT NOT NULL DEFAULT '',  -- evidence file reference, not content
  PRIMARY KEY (device_id, time_ns)
) WITHOUT ROWID;

-- Credential METADATA only. Secret values live in the vault, never here.
CREATE TABLE credentials (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  scope     TEXT NOT NULL,
  name      TEXT NOT NULL,
  scored    INTEGER NOT NULL DEFAULT 0,
  pcr_state TEXT NOT NULL DEFAULT '',
  vault_ref TEXT NOT NULL DEFAULT '',  -- opaque pointer into the vault
  rotated_ns INTEGER,
  UNIQUE (scope, name)
);
`,
	// 3: operator UI: accounts (argon2id PHC strings only) and the audit log
	`
CREATE TABLE ui_accounts (
  name       TEXT PRIMARY KEY,
  phc        TEXT NOT NULL,
  created_ns INTEGER NOT NULL
);
CREATE TABLE ui_audit (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  time_ns INTEGER NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  remote  TEXT NOT NULL DEFAULT '',
  detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ui_audit_time ON ui_audit(time_ns);
`,
	// 4: report/inject drafts, audit filters, alert source index
	`
CREATE TABLE report_drafts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,              -- incident | inject
  number     INTEGER NOT NULL,
  team       INTEGER NOT NULL,
  title      TEXT NOT NULL DEFAULT '',
  spec       TEXT NOT NULL,              -- JSON, owned by the controller
  created_by TEXT NOT NULL DEFAULT '',
  created_ns INTEGER NOT NULL,
  updated_ns INTEGER NOT NULL
);
CREATE INDEX report_drafts_kind ON report_drafts(kind, number);
CREATE INDEX ui_audit_actor ON ui_audit(actor, id);
CREATE INDEX ui_audit_action ON ui_audit(action, id);
CREATE INDEX alerts_source ON alerts(agent, seq);
`,
	// 5: envelope schema and tag (W1 Task 2). Events sealed before this
	// migration carry schema 0 and an empty tag, which their canonical
	// encoding omits, so their hashes still verify.
	`
ALTER TABLE events ADD COLUMN schema INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN tag TEXT NOT NULL DEFAULT '';
`,
	// 6: module table bookkeeping (W1 Task 8): how many of a module's own
	// migrations have been applied.
	`
CREATE TABLE module_migrations (
  module  TEXT PRIMARY KEY,
  applied INTEGER NOT NULL
);
`,
	// 7: one-click proposals (W1 Task 25). Evidence is a list of "agent:seq"
	// references; params is the template's parameter map.
	`
CREATE TABLE proposals (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  module     TEXT NOT NULL,
  title      TEXT NOT NULL,
  template   TEXT NOT NULL,
  params     TEXT NOT NULL DEFAULT '{}',
  evidence   TEXT NOT NULL DEFAULT '[]',
  reason     TEXT NOT NULL DEFAULT '',
  created_ns INTEGER NOT NULL,
  state      TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'dismissed')),
  plan_id    TEXT NOT NULL DEFAULT '',
  "by"       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX proposals_state_created ON proposals(state, created_ns);
`,
	// 8: standing approvals (W1 Task 24): an operator's one-time approval of a
	// module template, target labels and action list, until it expires.
	`
CREATE TABLE standing_approvals (
  id         TEXT PRIMARY KEY,
  module     TEXT NOT NULL,
  template   TEXT NOT NULL,
  targets    TEXT NOT NULL,
  actions    TEXT NOT NULL,             -- JSON array of action names
  expires_ns INTEGER NOT NULL,
  approver   TEXT NOT NULL,
  created    TEXT NOT NULL,             -- operator login
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX standing_expires ON standing_approvals(expires_ns);
`,
}
