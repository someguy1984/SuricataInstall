"""The hub database: one definition of every table (PLAN.md section 3).

Standard library only. Every module that reads or writes hub.db uses these names.
All times are integer epoch milliseconds (UTC) unless a column comment says otherwise.
JSON columns hold compact JSON text.
"""

# Version of this DDL. meta.schema_version holds the version of an existing file; the hub
# migrates forward one step per transaction and refuses a database newer than this (section 17).
SCHEMA_VERSION = 1

HOST_STATES = ("pending", "active", "moved", "retired", "revoked", "orphan")
# States whose certificate is still accepted on the fleet listener (section 2, Host states)
HOST_STATES_LIVE = ("pending", "active", "orphan")

INCIDENT_STATES = ("open", "acknowledged", "resolved")
OUTBOX_STATES = ("pending", "sending", "sent", "failed", "dead")
AUDIT_ACTOR_KINDS = ("cli", "ui", "system", "client")
AUDIT_OUTCOMES = ("ok", "denied", "invalid", "error")

# Pragmas for the single write connection, in the order section 3 requires.
# auto_vacuum must be set on a new file before journal_mode=WAL and before the first CREATE TABLE.
PRAGMAS_NEW_FILE = ("PRAGMA auto_vacuum=INCREMENTAL",)
PRAGMAS_WRITER = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=FULL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
    "PRAGMA cache_size=-20000",
    "PRAGMA mmap_size=0",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA journal_size_limit=1048576",
)

DDL = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
-- meta keys: schema_version, engine_cursor (events.id), writer_tick (ms), last_prune, last_quick_check,
--            last_daily_job, last_digest, pending_audit_offset, hub_started_at, hub_stopped_at,
--            last_backup (ms, copied from the last-backup marker), audit_head

CREATE TABLE hosts (
    uuid                   TEXT PRIMARY KEY,          -- minted by the hub; the certificate CN
    name                   TEXT NOT NULL UNIQUE,      -- the token's --name
    reported_name          TEXT NOT NULL DEFAULT '',  -- client hostname: display only, untrusted
    ips                    TEXT NOT NULL DEFAULT '[]',-- JSON list, client-claimed: display only
    peer_ips               TEXT NOT NULL DEFAULT '[]',-- JSON list, TCP sources the hub saw, at most 2
    os                     TEXT NOT NULL DEFAULT '',
    agent_version          TEXT,
    agent_sha256           TEXT,
    schema                 INTEGER,
    proto                  INTEGER,
    kernel                 TEXT,
    cert_sha256            TEXT,                      -- DER SHA-256 of the current certificate (the check)
    cert_serial            TEXT,                      -- hex, display
    cert_not_after         INTEGER,
    pending_cert_sha256    TEXT,                      -- issued by /v1/renew, current on first use
    pending_cert_serial    TEXT,
    pending_cert_not_after INTEGER,
    droplet_id             TEXT NOT NULL,             -- first seen at enrollment
    policy_rev             TEXT,                      -- revision last issued to the host
    policy_rev_since       INTEGER,
    policy_rev_applied     TEXT,                      -- from the heartbeat
    state                  TEXT NOT NULL CHECK (state IN ('pending','active','moved','retired','revoked','orphan')),
    state_since            INTEGER NOT NULL,
    enrolled_at            INTEGER NOT NULL,
    enrolled_from          TEXT NOT NULL DEFAULT '',  -- TCP peer at enrollment
    source_cidr            TEXT,                      -- the token's --source, if any
    skew_ms                INTEGER,
    last_seen              INTEGER,                   -- last accepted heartbeat
    first_heartbeat_at     INTEGER,
    last_seq               INTEGER,
    last_epoch             INTEGER,
    boot_id                TEXT,
    shutdown_notice_at     INTEGER                    -- last heartbeat with "shutdown": true
);

CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,                       -- hosts.uuid, from the certificate
    event_id     TEXT NOT NULL,                       -- the client's id, "<epoch hex>:<seq>"
    received_at  INTEGER NOT NULL,
    ts           INTEGER NOT NULL,                    -- after skew correction and clamp
    source       TEXT NOT NULL,
    severity     TEXT NOT NULL,                       -- the client's sev, never rewritten
    hub_severity TEXT NOT NULL,                       -- the hub's rating (equal to severity unless a rule rated it)
    rated_by     TEXT,                                -- the rule that set hub_severity, or NULL
    kind         TEXT NOT NULL,
    summary      TEXT NOT NULL DEFAULT '',
    details      TEXT NOT NULL DEFAULT '{}',          -- JSON object; proc, context, boot_id, redacted, truncated live here
    src_ip       TEXT NOT NULL DEFAULT '',
    src_trust    TEXT NOT NULL DEFAULT 'none',        -- tcp | claimed | none
    dst_ip       TEXT NOT NULL DEFAULT '',
    dst_port     INTEGER,
    proto        TEXT,
    community_id TEXT,
    epoch        INTEGER NOT NULL,
    seq          INTEGER NOT NULL,
    agent_ver    TEXT,
    count        INTEGER NOT NULL DEFAULT 1,
    first        INTEGER,                             -- from first_ts
    last         INTEGER,                             -- from last_ts
    replayed     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (host, event_id)
);
CREATE INDEX events_received ON events (received_at);
CREATE INDEX events_host_received ON events (host, received_at);
CREATE INDEX events_src_ip ON events (src_ip);

CREATE TABLE daily_counts (
    day    TEXT NOT NULL,                             -- YYYY-MM-DD (UTC) of received_at
    host   TEXT NOT NULL,
    source TEXT NOT NULL,
    kind   TEXT NOT NULL,
    count  INTEGER NOT NULL,
    PRIMARY KEY (day, host, source, kind)
) WITHOUT ROWID;

CREATE TABLE heartbeats (                             -- latest heartbeat per host
    host        TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL,
    peer_ip     TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL                         -- the validated heartbeat JSON, without inventory
) WITHOUT ROWID;

CREATE TABLE heartbeat_samples (                      -- one sample per 5 minutes, kept 24 h
    host        TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    body        TEXT NOT NULL,
    PRIMARY KEY (host, received_at)
) WITHOUT ROWID;

CREATE TABLE inventory (                              -- latest inventory object per host
    host        TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL,
    body        TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE bans (                                   -- filled from P3; empty in P2
    cidr       TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',              -- free text, stays on the hub
    source     TEXT NOT NULL,                         -- fleet | operator
    created    INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID;

CREATE TABLE feeds (                                  -- filled from P3
    name       TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'never',
    last_fetch INTEGER,
    last_good  INTEGER,
    count      INTEGER NOT NULL DEFAULT 0,
    checksum   TEXT,
    entries    TEXT NOT NULL DEFAULT '[]'
) WITHOUT ROWID;

CREATE TABLE tokens (
    id            TEXT PRIMARY KEY,
    secret_sha256 TEXT NOT NULL,
    name          TEXT,                               -- host name a new host will get (NULL with bound_host)
    bound_host    TEXT,                               -- hosts.uuid for a token made --for HOST
    source_cidr   TEXT,
    created_at    INTEGER NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',
    expires_at    INTEGER NOT NULL,
    used_by       TEXT,                               -- hosts.uuid
    used_at       INTEGER,
    used_from     TEXT,                               -- TCP peer
    csr_sha256    TEXT,
    issued_reply  TEXT,                               -- the enroll reply JSON, for the 10-minute replay
    bad_attempts  INTEGER NOT NULL DEFAULT 0,         -- five wrong secrets burn the id
    revoked_at    INTEGER
) WITHOUT ROWID;

CREATE TABLE incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    chain      TEXT NOT NULL,                         -- rule chain name; the key is (host, chain)
    opened     INTEGER NOT NULL,
    updated    INTEGER NOT NULL,                      -- last signal
    state      TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','acknowledged','resolved')),
    severity   TEXT NOT NULL,
    kinds      TEXT NOT NULL DEFAULT '[]',            -- JSON list of distinct signal kinds
    signals    INTEGER NOT NULL DEFAULT 0,            -- sum of count over member events
    title      TEXT NOT NULL DEFAULT '',
    ack_by     TEXT,
    ack_until  INTEGER,
    closed_at  INTEGER,
    closed_by  TEXT,
    note       TEXT NOT NULL DEFAULT '',
    repeats    INTEGER NOT NULL DEFAULT 0,            -- CRITICAL repeat alerts sent (P3)
    last_alert INTEGER
);
CREATE INDEX incidents_host_state ON incidents (host, state);

CREATE TABLE incident_events (                        -- pins events against pruning
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_rowid INTEGER NOT NULL,                     -- events.id
    PRIMARY KEY (incident_id, event_rowid)
) WITHOUT ROWID;
CREATE INDEX incident_events_event ON incident_events (event_rowid);

CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created    INTEGER NOT NULL,
    channel    TEXT NOT NULL,                         -- webhook | ntfy | discord | email | none
    severity   TEXT NOT NULL,
    payload    TEXT NOT NULL,                         -- JSON, see the alert payload in hub_alerts
    dedup_key  TEXT,
    attempts   INTEGER NOT NULL DEFAULT 0,
    next_try   INTEGER NOT NULL,
    state      TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sending','sent','failed','dead')),
    last_error TEXT NOT NULL DEFAULT '',
    sent_at    INTEGER
);
CREATE INDEX outbox_state_next ON outbox (state, next_try);

CREATE TABLE login_codes (
    code_sha256 TEXT PRIMARY KEY,
    created     INTEGER NOT NULL,
    expires     INTEGER NOT NULL,
    used_at     INTEGER
) WITHOUT ROWID;

CREATE TABLE never_ban (
    cidr     TEXT PRIMARY KEY,
    reason   TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL DEFAULT '',
    ts       INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE settings_history (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    INTEGER NOT NULL,
    key   TEXT NOT NULL,
    old   TEXT,                                       -- "changed" for a secret key, never the value
    new   TEXT,
    actor TEXT NOT NULL DEFAULT ''
);

CREATE TABLE agent_hashes (                           -- local overrides; the shipped list is agent-hashes.json
    sha256   TEXT PRIMARY KEY,
    note     TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL DEFAULT '',
    ts       INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE alert_state (                            -- dedup and storm control
    key        TEXT PRIMARY KEY,                      -- for example "<host>|<kind>" or "storm"
    severity   TEXT NOT NULL DEFAULT '',
    first      INTEGER NOT NULL,
    last       INTEGER NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    suppressed INTEGER NOT NULL DEFAULT 0,
    data       TEXT NOT NULL DEFAULT '{}'
) WITHOUT ROWID;

CREATE TABLE ban_votes (                              -- P3
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host     TEXT NOT NULL,
    ip       TEXT NOT NULL,
    evidence TEXT NOT NULL,
    ts       INTEGER NOT NULL
);

CREATE TABLE maintenance (
    host   TEXT PRIMARY KEY,
    until  INTEGER NOT NULL,
    set_by TEXT NOT NULL,                             -- operator (cli login uid or ui session); never the host itself
    set_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    actor_kind   TEXT NOT NULL CHECK (actor_kind IN ('cli','ui','system','client')),
    actor_detail TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    target       TEXT NOT NULL DEFAULT '',
    outcome      TEXT NOT NULL CHECK (outcome IN ('ok','denied','invalid','error')),
    details      TEXT NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
CREATE INDEX audit_ts ON audit (ts);

CREATE TABLE pending_audit_seen (                     -- line ids already ingested from pending-audit.jsonl
    line_id TEXT PRIMARY KEY,
    ts      INTEGER NOT NULL
) WITHOUT ROWID;
"""
