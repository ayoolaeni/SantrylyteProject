# SentryLite — Real-Time Security Incident Response & Log Triage Dashboard

> **Purpose of this document**
> This README is a complete build specification. It is written so that an AI coding agent (or a developer) can implement the entire application from this file alone, without access to the original academic project report. Every requirement below is numbered and traceable to the project's functional requirements (FR1–FR14) and non-functional requirements (NFR1–NFR7).
>
> **Instruction to the implementing AI:** Build the system exactly as specified. Where a detail is not specified, choose the simplest option consistent with the stated tech stack, and record the decision in `DECISIONS.md`. Do not substitute the tech stack. Do not introduce paid services. Follow the build order in Section 14.

---

## 1. Project Overview

**SentryLite** is a lightweight, self-hostable web application that ingests logs from multiple sources in real time, normalises them into a single event schema, automatically scores and prioritises them using a configurable rule engine, streams them to a live browser dashboard, and manages the resulting incidents through a structured response workflow.

It targets small and medium organisations and academic institutions that cannot afford or operate a commercial SIEM.

### 1.1 What the system must do
1. Receive logs over **syslog (UDP + TCP)** and over an authenticated **REST ingestion endpoint**.
2. **Parse and normalise** four log families into one common event schema.
3. **Triage** every event with a weighted rule engine that produces a numeric `severity_score` and a `priority_level` of `INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL`.
4. **Persist** all events, incidents, users, rules and audit actions.
5. **Stream** triaged events to connected browsers over WebSocket with sub-two-second end-to-end latency.
6. Present a **real-time dashboard**, a **filterable prioritised alert queue**, and an **incident detail workspace**.
7. Support the **incident life cycle**: New → Acknowledged → Investigating → (Escalated | False Positive | Resolved) → Closed.
8. Enforce **authentication and role-based access control** (Analyst, Administrator, plus read-only Viewer).
9. Provide **admin configuration** of log sources, triage rules, critical assets and users.
10. Generate **summary reports** over a selected period, exportable as CSV and PDF.

### 1.2 Explicit non-goals
- No machine-learning anomaly detection (leave clean extension points only).
- No automated active remediation (no host isolation, no firewall changes).
- No agent software for endpoints — sources push to us, we do not pull.
- No multi-tenancy.

---

## 2. Technology Stack (fixed — do not substitute)

| Layer | Technology | Notes |
|---|---|---|
| Backend language | **Python 3.11+** | |
| Web framework | **Flask 3.x** | Application-factory pattern, Blueprints |
| Real-time | **Flask-SocketIO** + **eventlet** | WebSocket push |
| ORM | **SQLAlchemy 2.x** + **Flask-SQLAlchemy** | |
| Migrations | **Alembic** (via Flask-Migrate) | |
| Database | **PostgreSQL 15** in production, **SQLite** in dev | Config-switchable via `DATABASE_URL` |
| Background queue | **Python `queue.Queue` + worker threads** | No Redis/Celery dependency (keeps deployment light). Design the ingestion→triage handoff behind an interface so a Redis-backed queue can be dropped in later. |
| Auth | **Flask-Login** + **Werkzeug** password hashing (`pbkdf2:sha256`) | Sessions, CSRF via **Flask-WTF** |
| Frontend | **HTML5 + CSS3 + vanilla JavaScript (ES6 modules)** | No React/Vue build step |
| Charts | **Chart.js 4** | |
| Socket client | **socket.io-client** | |
| Testing | **pytest**, **pytest-cov**, **Flask test client** | |
| Linting | **ruff** + **black** | |
| Containerisation | **Docker** + **docker-compose** | |
| Version control | **git** | Conventional Commits |

**Dependency rule:** every dependency must be free and open-source. Pin versions in `requirements.txt`.

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          LOG SOURCES                                 │
│   Linux syslog · Web server access logs · Auth logs · JSON apps      │
└───────────────┬──────────────────────────────┬───────────────────────┘
                │ UDP/TCP 514 (dev: 5514)      │ HTTPS POST /api/v1/ingest
                ▼                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  1. INGESTION LAYER    (syslog_server.py, ingest_api.py)             │
│     - Accepts raw messages, tags with source_id + received_at        │
│     - Pushes onto bounded in-memory RawQueue (maxsize configurable)  │
│     - On queue-full: spill to disk buffer (NFR4 — no data loss)      │
└───────────────┬──────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  2. PARSING & NORMALISATION  (parsers/)                              │
│     - Detects/uses source format, extracts fields                    │
│     - Emits NormalisedEvent object; failures → error queue + DLQ     │
└───────────────┬──────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  3. TRIAGE ENGINE  (triage/engine.py)                                │
│     - Evaluates enabled rules, sums weights                          │
│     - Applies contextual modifiers (critical asset, off-hours,       │
│       repetition within sliding window)                              │
│     - Assigns priority from thresholds; auto-creates CRITICAL        │
│       incidents                                                      │
└───────┬───────────────────────────────────────────┬──────────────────┘
        ▼                                           ▼
┌────────────────────┐                   ┌──────────────────────────────┐
│  4. DATABASE       │                   │  5. REAL-TIME PUSH LAYER     │
│  PostgreSQL/SQLite │                   │  Flask-SocketIO rooms        │
└─────────┬──────────┘                   └───────────────┬──────────────┘
          │                                              │
          ▼                                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  6. APPLICATION SERVER / REST API (Flask Blueprints)                 │
│  7. DASHBOARD (browser: dashboard · alert queue · incidents · admin) │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.1 Threading model
- Main process runs Flask + SocketIO under eventlet.
- One thread for the UDP syslog listener, one for the TCP syslog listener.
- A pool of **N worker threads** (default 4, `TRIAGE_WORKERS` env var) drain `RawQueue`, parse, triage, persist, then emit the SocketIO event.
- All DB writes inside workers use a scoped session created per batch; commit in batches of up to 50 events or every 500 ms, whichever comes first (this is how NFR2 is met).

---

## 4. Repository Layout

```
sentrylite/
├── README.md
├── DECISIONS.md
├── requirements.txt
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── run.py                       # entrypoint: socketio.run(app)
├── config.py                    # Dev / Test / Prod config classes
├── migrations/                  # Alembic
├── app/
│   ├── __init__.py              # create_app() application factory
│   ├── extensions.py            # db, migrate, login_manager, socketio, csrf
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── log_source.py
│   │   ├── event.py
│   │   ├── triage_rule.py
│   │   ├── incident.py
│   │   ├── incident_action.py
│   │   └── critical_asset.py
│   ├── ingestion/
│   │   ├── queue.py             # RawQueue + disk spill buffer
│   │   ├── syslog_server.py     # UDP + TCP listeners
│   │   └── worker.py            # worker thread loop
│   ├── parsers/
│   │   ├── base.py              # Parser ABC + NormalisedEvent dataclass
│   │   ├── syslog_rfc3164.py
│   │   ├── syslog_rfc5424.py
│   │   ├── auth_log.py          # Linux /var/log/auth.log & secure
│   │   ├── nginx_access.py      # combined log format
│   │   ├── apache_access.py
│   │   ├── json_generic.py
│   │   ├── windows_evtx_json.py # JSON-exported Windows security events
│   │   └── registry.py          # format detection + dispatch
│   ├── triage/
│   │   ├── engine.py
│   │   ├── conditions.py        # condition DSL evaluator
│   │   ├── modifiers.py
│   │   └── correlator.py        # sliding-window state (failed logins, scans)
│   ├── api/
│   │   ├── __init__.py
│   │   ├── ingest.py            # POST /api/v1/ingest
│   │   ├── events.py
│   │   ├── incidents.py
│   │   ├── rules.py
│   │   ├── sources.py
│   │   ├── users.py
│   │   ├── stats.py
│   │   └── reports.py
│   ├── views/                   # server-rendered page shells
│   │   ├── auth.py
│   │   ├── dashboard.py
│   │   ├── alerts.py
│   │   ├── incidents.py
│   │   └── admin.py
│   ├── realtime/
│   │   └── events.py            # SocketIO handlers + emit helpers
│   ├── security/
│   │   ├── rbac.py              # @role_required decorator
│   │   └── audit.py
│   ├── static/
│   │   ├── css/main.css
│   │   ├── js/{dashboard,alerts,incident,admin,socket,api}.js
│   │   └── img/
│   └── templates/
│       ├── base.html
│       ├── auth/login.html
│       ├── dashboard.html
│       ├── alerts.html
│       ├── incident_detail.html
│       ├── reports.html
│       └── admin/{sources,rules,users,assets}.html
├── seeds/
│   ├── seed_rules.py            # loads the 12 default rules
│   ├── seed_users.py
│   └── sample_logs/             # small representative log files
├── tools/
│   ├── log_generator.py         # synthetic benign + attack traffic
│   └── load_test.py             # measures throughput & latency (NFR1, NFR2)
└── tests/
    ├── conftest.py
    ├── test_parsers.py
    ├── test_triage_engine.py
    ├── test_correlator.py
    ├── test_api_events.py
    ├── test_api_incidents.py
    ├── test_auth_rbac.py
    ├── test_realtime.py
    └── test_performance.py
```

---

## 5. Data Model

Normalise to 3NF. Use `BIGINT` identity PKs for `event`, `INT` elsewhere. All timestamps stored **UTC, timezone-aware**.

### 5.1 `user`
| Field | Type | Constraint | Description |
|---|---|---|---|
| user_id | INT | PK | |
| username | VARCHAR(50) | UNIQUE, NOT NULL | |
| email | VARCHAR(120) | UNIQUE, NOT NULL | |
| full_name | VARCHAR(120) | NOT NULL | |
| password_hash | VARCHAR(255) | NOT NULL | pbkdf2:sha256, per-user salt |
| role | VARCHAR(20) | NOT NULL | `ADMIN` \| `ANALYST` \| `VIEWER` |
| is_active | BOOLEAN | NOT NULL, default true | |
| last_login_at | TIMESTAMPTZ | NULL | |
| failed_login_count | INT | NOT NULL, default 0 | lock after 5 for 15 min |
| created_at | TIMESTAMPTZ | NOT NULL | |

### 5.2 `log_source`
| Field | Type | Constraint | Description |
|---|---|---|---|
| source_id | INT | PK | |
| name | VARCHAR(100) | UNIQUE, NOT NULL | e.g. "web-01 nginx" |
| host_identifier | VARCHAR(255) | NOT NULL | IP or hostname we match on |
| source_type | VARCHAR(40) | NOT NULL | `SYSLOG` \| `AUTH_LOG` \| `NGINX_ACCESS` \| `APACHE_ACCESS` \| `JSON_GENERIC` \| `WINDOWS_JSON` |
| ingest_token | VARCHAR(64) | UNIQUE, NULL | bearer token for REST ingestion |
| is_enabled | BOOLEAN | NOT NULL, default true | |
| last_seen_at | TIMESTAMPTZ | NULL | drives "source silent" health check |
| created_at | TIMESTAMPTZ | NOT NULL | |

### 5.3 `event` (principal table)
| Field | Type | Constraint | Description |
|---|---|---|---|
| event_id | BIGINT | PK | |
| source_id | INT | FK → log_source | |
| timestamp | TIMESTAMPTZ | NOT NULL, INDEX | time event occurred (from log) |
| received_at | TIMESTAMPTZ | NOT NULL | time we ingested it |
| event_type | VARCHAR(50) | NOT NULL, INDEX | normalised category (§5.8) |
| src_ip | VARCHAR(45) | NULL, INDEX | IPv4/IPv6 |
| dest_ip | VARCHAR(45) | NULL | |
| dest_port | INT | NULL | |
| username | VARCHAR(100) | NULL, INDEX | |
| hostname | VARCHAR(255) | NULL | |
| protocol | VARCHAR(10) | NULL | |
| action | VARCHAR(30) | NULL | `ALLOW`/`DENY`/`SUCCESS`/`FAILURE` |
| http_method | VARCHAR(10) | NULL | |
| http_path | TEXT | NULL | |
| http_status | INT | NULL | |
| bytes | BIGINT | NULL | |
| user_agent | TEXT | NULL | |
| message | TEXT | NULL | human-readable summary |
| raw_message | TEXT | NOT NULL | original, unmodified |
| matched_rules | JSON | NULL | `[{rule_id, name, weight}]` |
| modifiers_applied | JSON | NULL | `[{name, effect}]` |
| severity_score | NUMERIC(6,2) | NOT NULL, INDEX | |
| priority_level | VARCHAR(15) | NOT NULL, INDEX | |
| status | VARCHAR(20) | NOT NULL | `NEW` \| `ACKNOWLEDGED` \| `ESCALATED` \| `DISMISSED` |

Composite index on `(priority_level, timestamp DESC)` — this backs the alert queue.
Composite index on `(src_ip, timestamp)` — this backs the correlator.

### 5.4 `triage_rule`
| Field | Type | Constraint | Description |
|---|---|---|---|
| rule_id | INT | PK | |
| name | VARCHAR(100) | UNIQUE, NOT NULL | |
| description | TEXT | NULL | |
| condition | JSON | NOT NULL | see condition DSL, §6.2 |
| weight | NUMERIC(6,2) | NOT NULL | |
| category | VARCHAR(50) | NOT NULL | e.g. `AUTHENTICATION`, `RECON`, `WEB_ATTACK` |
| mitre_technique | VARCHAR(20) | NULL | e.g. `T1110` — nice-to-have mapping |
| is_enabled | BOOLEAN | NOT NULL, default true | |
| created_by | INT | FK → user, NULL | |
| created_at / updated_at | TIMESTAMPTZ | NOT NULL | |

### 5.5 `incident`
| Field | Type | Constraint | Description |
|---|---|---|---|
| incident_id | INT | PK | |
| reference | VARCHAR(20) | UNIQUE, NOT NULL | `INC-2026-000123` |
| title | VARCHAR(200) | NOT NULL | auto-generated from event, editable |
| description | TEXT | NULL | |
| originating_event_id | BIGINT | FK → event, NOT NULL | |
| priority_level | VARCHAR(15) | NOT NULL | inherited, admin-overridable |
| state | VARCHAR(20) | NOT NULL | see §7 |
| assigned_to | INT | FK → user, NULL | |
| created_by | INT | FK → user, NULL | NULL = auto-created by engine |
| created_at | TIMESTAMPTZ | NOT NULL | |
| acknowledged_at | TIMESTAMPTZ | NULL | drives MTTA metric |
| resolved_at | TIMESTAMPTZ | NULL | drives MTTR metric |
| closed_at | TIMESTAMPTZ | NULL | |
| resolution_summary | TEXT | NULL | required to close |

Also create link table `incident_event (incident_id, event_id)` so related events can be attached to an incident during investigation.

### 5.6 `incident_action` (audit trail — FR11)
| Field | Type | Constraint | Description |
|---|---|---|---|
| action_id | BIGINT | PK | |
| incident_id | INT | FK → incident, NOT NULL | |
| user_id | INT | FK → user, NOT NULL | |
| action_type | VARCHAR(30) | NOT NULL | `CREATED` `ACKNOWLEDGED` `ASSIGNED` `COMMENTED` `ESCALATED` `STATE_CHANGED` `EVENT_LINKED` `RESOLVED` `CLOSED` `REOPENED` |
| from_value / to_value | VARCHAR(100) | NULL | for state/assignment changes |
| comment | TEXT | NULL | |
| created_at | TIMESTAMPTZ | NOT NULL | |

Rows in this table are **append-only**: expose no update or delete path anywhere in the API or UI.

### 5.7 `critical_asset`
| Field | Type | Constraint | Description |
|---|---|---|---|
| asset_id | INT | PK | |
| identifier | VARCHAR(255) | UNIQUE, NOT NULL | IP, CIDR or hostname |
| label | VARCHAR(100) | NOT NULL | |
| criticality_multiplier | NUMERIC(3,2) | NOT NULL, default 1.50 | |
| is_enabled | BOOLEAN | NOT NULL, default true | |

### 5.8 Controlled vocabulary for `event_type`
`AUTH_SUCCESS`, `AUTH_FAILURE`, `AUTH_LOGOUT`, `PRIVILEGE_CHANGE`, `ACCOUNT_CREATED`, `ACCOUNT_LOCKED`, `FILE_ACCESS`, `PROCESS_EXEC`, `NETWORK_CONNECTION`, `FIREWALL_DENY`, `WEB_REQUEST`, `WEB_ERROR`, `SERVICE_START`, `SERVICE_STOP`, `CONFIG_CHANGE`, `MALWARE_ALERT`, `SYSTEM_ERROR`, `OTHER`.

Parsers **must** map to one of these; unknown → `OTHER`.

---

## 6. Triage Engine

### 6.1 Algorithm (implement exactly)

```
BEGIN Triage(raw_event, source)
    normalised ← Parse(raw_event, source)
    IF normalised IS NULL THEN
        WriteToDeadLetterQueue(raw_event); RETURN
    END IF

    score ← 0
    matched ← []
    FOR EACH rule IN EnabledRules DO
        IF Matches(normalised, rule.condition) THEN
            score ← score + rule.weight
            matched.append(rule)
        END IF
    END FOR

    -- contextual modifiers, applied in this order
    IF IsCriticalAsset(normalised.dest_ip OR normalised.hostname) THEN
        score ← score × asset.criticality_multiplier      -- default 1.5
    IF IsOutsideWorkingHours(normalised.timestamp) THEN
        score ← score + 10                                -- default window 08:00–18:00 Mon–Fri
    IF RepeatCount(normalised.src_ip, WINDOW) > REPEAT_LIMIT THEN
        score ← score + 20                                -- default WINDOW=120s, LIMIT=10

    score ← Clamp(score, 0, 200)

    IF   score ≥ 90 THEN priority ← CRITICAL
    ELIF score ≥ 65 THEN priority ← HIGH
    ELIF score ≥ 40 THEN priority ← MEDIUM
    ELIF score ≥ 15 THEN priority ← LOW
    ELSE                 priority ← INFORMATIONAL

    normalised.severity_score ← score
    normalised.priority_level ← priority
    normalised.matched_rules  ← matched
    Persist(normalised)

    IF priority = CRITICAL THEN
        incident ← CreateIncident(normalised)   -- state = NEW, created_by = NULL
        Notify(all connected analysts)
    ELIF priority IN (HIGH, MEDIUM, LOW) THEN
        AddToAlertQueue(normalised)
    END IF

    StreamToDashboard(normalised)
END
```

All thresholds, the working-hours window, the repeat window/limit and the clamp ceiling must live in `config.py` and be **overridable by environment variable** — testing will tune them.

### 6.2 Condition DSL
Rule conditions are stored as JSON so administrators can edit rules without code changes (FR13). Support this grammar:

```json
{
  "all": [
    { "field": "event_type", "op": "eq",       "value": "AUTH_FAILURE" },
    { "field": "src_ip",     "op": "not_in_cidr", "value": "10.0.0.0/8" },
    { "any": [
        { "field": "http_path", "op": "regex", "value": "(\\.\\./|%2e%2e)" },
        { "field": "http_status", "op": "gte", "value": 500 }
    ]}
  ],
  "correlation": {
    "type": "threshold",
    "group_by": "src_ip",
    "count": 5,
    "window_seconds": 120
  }
}
```

Operators to implement: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `not_contains`, `startswith`, `endswith`, `regex`, `in_cidr`, `not_in_cidr`, `exists`, `is_null`.
Combinators: `all` (AND), `any` (OR), `none` (NOT).
Correlation types: `threshold` (N matches grouped by field within window), `distinct_count` (N distinct values of `distinct_field` within window — used for port scans), `sequence` (event A followed by event B from same `group_by` within window — used for "successful login after failures").

**Safety:** compile regexes with a timeout guard or use `re` with pre-validation rejecting catastrophic backtracking patterns; never `eval()` a rule.

### 6.3 Default rule set (seed these — `seeds/seed_rules.py`)

| # | Name | Category | Condition (summary) | Weight |
|---|---|---|---|---|
| 1 | Repeated failed login | AUTHENTICATION | > 5 `AUTH_FAILURE` from one `src_ip` in 120 s | 40 |
| 2 | Successful login after failures | AUTHENTICATION | `AUTH_SUCCESS` within 120 s of ≥ 5 `AUTH_FAILURE` from same `src_ip` | 70 |
| 3 | Privilege escalation | PRIVILEGE | `PRIVILEGE_CHANGE` where target group is administrative | 60 |
| 4 | Port scan pattern | RECON | > 15 distinct `dest_port` from one `src_ip` in 60 s | 35 |
| 5 | Directory traversal | WEB_ATTACK | `http_path` matches `(\.\./\|%2e%2e\|\.\.\\)` | 50 |
| 6 | Malformed / oversized request | WEB_ATTACK | request length > 4096 chars | 20 |
| 7 | Log service stopped | DEFENCE_EVASION | `SERVICE_STOP` where service is a logging service | 65 |
| 8 | Sensitive file access | DATA_ACCESS | `FILE_ACCESS` on protected path list | 45 |
| 9 | SQL injection attempt | WEB_ATTACK | `http_path` or query matches `(union\s+select\|' or '1'='1\|sleep\()` | 55 |
| 10 | Root / admin login from external IP | AUTHENTICATION | `AUTH_SUCCESS` + username in (`root`,`admin`,`administrator`) + `src_ip` not in internal CIDR | 60 |
| 11 | Account created outside change window | ACCOUNT | `ACCOUNT_CREATED` outside working hours | 45 |
| 12 | Web brute force | WEB_ATTACK | > 20 responses with `http_status` 401/403 from one `src_ip` in 60 s | 35 |

Weights are **initial values**; the admin UI must allow tuning them at runtime, and changes must take effect within 30 seconds without restart (cache rules with a TTL or invalidate on write).

### 6.4 Correlator implementation notes
Keep sliding-window state **in memory** in `triage/correlator.py`: a dict of `deque[(timestamp, value)]` keyed by `(rule_id, group_value)`, pruned on every access and by a periodic sweeper every 60 s. Cap total tracked keys (`CORRELATOR_MAX_KEYS`, default 50 000) and evict least-recently-used beyond that, so memory cannot grow unbounded. State loss on restart is acceptable — document it.

---

## 7. Incident Life Cycle

```
      ┌─────┐  acknowledge   ┌──────────────┐  begin work  ┌───────────────┐
      │ NEW ├───────────────►│ ACKNOWLEDGED ├─────────────►│ INVESTIGATING │
      └─────┘                └──────────────┘              └───┬───┬───┬───┘
                                                               │   │   │
                       escalate ◄──────────────────────────────┘   │   └────────► FALSE_POSITIVE
                          │                                        │                    │
                     ┌────▼─────┐                             ┌────▼─────┐              │
                     │ESCALATED │────────────────────────────►│ RESOLVED │              │
                     └──────────┘        remediate            └────┬─────┘              │
                                                                   │ verify             │
                                                              ┌────▼─────┐              │
                                                              │  CLOSED  │◄─────────────┘
                                                              └────┬─────┘
                                                                   │ reopen (ADMIN only)
                                                                   └────► INVESTIGATING
```

**Allowed transitions (enforce server-side; reject others with HTTP 409):**

| From | To | Who |
|---|---|---|
| NEW | ACKNOWLEDGED | ANALYST, ADMIN |
| ACKNOWLEDGED | INVESTIGATING, FALSE_POSITIVE | ANALYST, ADMIN |
| INVESTIGATING | ESCALATED, RESOLVED, FALSE_POSITIVE | ANALYST, ADMIN |
| ESCALATED | INVESTIGATING, RESOLVED | ANALYST, ADMIN |
| RESOLVED | CLOSED, INVESTIGATING | ANALYST, ADMIN |
| FALSE_POSITIVE | CLOSED | ANALYST, ADMIN |
| CLOSED | INVESTIGATING (reopen) | ADMIN only |

Rules:
- `RESOLVED` and `FALSE_POSITIVE` require a non-empty `resolution_summary`.
- Every transition writes an `incident_action` row.
- Setting `acknowledged_at` happens once, on first entry to ACKNOWLEDGED.

---

## 8. REST API

Base path `/api/v1`. JSON in, JSON out. Session-cookie auth for the UI; bearer-token auth for ingestion only. All non-GET UI routes require a CSRF token.

### 8.1 Ingestion
```
POST /api/v1/ingest
Authorization: Bearer <log_source.ingest_token>
Content-Type: application/json

Single:  { "message": "...", "timestamp": "2026-08-05T10:11:12Z" }
Batch:   { "events": [ {...}, {...} ] }     # max 500 per request

202 Accepted → { "accepted": 137, "rejected": 0 }
429 if source exceeds rate limit
```
Accept `text/plain` bodies too (raw syslog line). Never block: enqueue and return.

### 8.2 Events
```
GET  /api/v1/events?priority=HIGH,CRITICAL&source_id=3&event_type=AUTH_FAILURE
                   &src_ip=1.2.3.4&status=NEW&from=ISO&to=ISO
                   &q=free-text&sort=-severity_score&page=1&per_page=50
GET  /api/v1/events/<event_id>
POST /api/v1/events/<event_id>/acknowledge
POST /api/v1/events/<event_id>/dismiss        { "reason": "..." }
POST /api/v1/events/<event_id>/create-incident { "title": "...", "assign_to": 4 }
```
All list endpoints return `{ "data": [...], "page": 1, "per_page": 50, "total": 1234 }`.

### 8.3 Incidents
```
GET   /api/v1/incidents?state=&priority=&assigned_to=me&from=&to=&page=
GET   /api/v1/incidents/<id>            # includes actions[] and linked events[]
POST  /api/v1/incidents                 # manual creation
PATCH /api/v1/incidents/<id>            { title, description, priority_level }
POST  /api/v1/incidents/<id>/transition { "to_state": "RESOLVED", "resolution_summary": "..." }
POST  /api/v1/incidents/<id>/assign     { "user_id": 4 }
POST  /api/v1/incidents/<id>/comment    { "comment": "..." }
POST  /api/v1/incidents/<id>/link-event { "event_id": 99 }
```

### 8.4 Statistics (dashboard)
```
GET /api/v1/stats/summary        → counts of open incidents by priority, events last 24h,
                                    MTTA, MTTR, sources online/silent
GET /api/v1/stats/timeseries?interval=1m&window=1h   → event volume per bucket per priority
GET /api/v1/stats/priority-distribution?window=24h
GET /api/v1/stats/top-sources?limit=10&window=24h
GET /api/v1/stats/top-attackers?limit=10&window=24h   → by src_ip and summed severity
```

### 8.5 Administration (ADMIN role only)
```
GET/POST/PATCH/DELETE  /api/v1/rules  and  /api/v1/rules/<id>
POST /api/v1/rules/<id>/test          { "sample_event": {...} } → { matched: true, weight: 40 }
GET/POST/PATCH/DELETE  /api/v1/sources    (POST returns freshly generated ingest_token)
POST /api/v1/sources/<id>/rotate-token
GET/POST/PATCH/DELETE  /api/v1/users
GET/POST/PATCH/DELETE  /api/v1/assets
```

### 8.6 Reports (FR14)
```
GET /api/v1/reports/incidents?from=&to=&format=json|csv|pdf
```
Report contents: total incidents by priority and state, MTTA/MTTR, top 10 rules by trigger count, top 10 source IPs, incident list with reference, title, priority, assignee, created/closed timestamps.

### 8.7 Error format
```json
{ "error": { "code": "INVALID_TRANSITION", "message": "Cannot move CLOSED → RESOLVED", "details": {} } }
```
Use HTTP 400 / 401 / 403 / 404 / 409 / 422 / 429 / 500 correctly.

---

## 9. Real-Time Layer (WebSocket)

Namespace `/live`. On connect, authenticate from the Flask session; reject anonymous sockets.

**Rooms:** `all_events`, `priority_critical`, `priority_high`, `incidents`, `user_<id>`.

**Server → client events**

| Event | Payload | When |
|---|---|---|
| `event:new` | compact event object (id, ts, type, src_ip, priority, score, message) | every triaged event, to `all_events` |
| `alert:high` | event object | priority HIGH or CRITICAL |
| `incident:created` | incident summary | auto or manual creation |
| `incident:updated` | `{incident_id, state, assigned_to, updated_by}` | any transition/assignment |
| `stats:tick` | summary counters | every 5 s |
| `source:silent` | `{source_id, name, last_seen_at}` | no data for > 15 min |

**Client → server events:** `subscribe` / `unsubscribe` with `{rooms: [...]}`.

**Backpressure:** if a client is slow, coalesce `event:new` into batched emits of up to 25 events every 250 ms rather than one emit per event.

**Reconnection:** the client must, on reconnect, call `GET /api/v1/events?from=<last_seen_ts>` to backfill the gap.

---

## 10. Frontend Specification

Server-rendered Jinja shells, hydrated by ES6 modules. No build step. Dark-first theme with a light toggle.

### 10.1 Design tokens
```css
:root{
  --bg:#0f1419; --surface:#171d26; --surface-2:#1f2733; --border:#2a3441;
  --text:#e6edf3; --text-muted:#8b98a5;
  --critical:#e5484d; --high:#f76808; --medium:#f5d90a; --low:#3b9eff; --info:#8b98a5;
  --ok:#30a46c;
  --font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, "JetBrains Mono", Menlo, monospace;
}
```
**Accessibility (mandatory):** priority is *never* conveyed by colour alone — always pair the colour with a text label and a distinct icon/shape. Maintain WCAG AA contrast. All interactive elements keyboard-reachable with visible focus rings. Live regions announced with `aria-live="polite"`.

### 10.2 Screens

**A. Login** — username, password, error messaging, lockout notice after 5 failures. No user enumeration in error text.

**B. Dashboard (`/`)** — the primary screen:
- Top row: five KPI cards — Open Critical, Open High, Events (24 h), MTTA, MTTR. Each card is a link into a pre-filtered alert queue.
- Row 2: stacked area/line chart of event volume per minute over the last hour, coloured by priority (Chart.js, streaming update, max 60 points, no full re-render — use `chart.update('none')`).
- Row 3, left: doughnut of priority distribution (24 h). Right: horizontal bar of top 10 talkers by `src_ip`.
- Row 4: **live event feed** — a virtualised list capped at 200 rows in the DOM, newest at top, each row showing time, priority pill, source, event type, `src_ip`, and truncated message. Rows are clickable → event detail drawer. Include a **pause/resume** toggle so an analyst can read without the list scrolling away.
- A toast + optional browser notification (with permission prompt) on `alert:high`.

**C. Alert Queue (`/alerts`)** — table sorted by `severity_score` DESC then time DESC. Sticky filter bar: priority (multi), source, event type, status, time range, free-text. Bulk-select with bulk acknowledge/dismiss. Row actions: Acknowledge · Dismiss (false positive, requires reason) · Create Incident. URL reflects filter state so views are shareable.

**D. Incident Detail (`/incidents/<ref>`)** — two columns.
Left: originating event card with all normalised fields and the raw message in a `<pre>` monospace block with a copy button; the list of matched rules with their weights and the modifiers applied (this is the "why was this scored 92?" explanation — do not omit it); linked related events.
Right: state badge and permitted transition buttons only; assignee selector; priority override (ADMIN); comment composer; and the full chronological **audit timeline** of `incident_action` rows with actor and timestamp.

**E. Incidents list (`/incidents`)** — filterable table; default filter "assigned to me, not closed".

**F. Admin (`/admin/*`)** — CRUD for rules (with a JSON condition editor plus the "test rule against sample event" button), sources (with token display shown exactly once on creation), critical assets, and users.

**G. Reports (`/reports`)** — date-range picker, on-screen summary, CSV and PDF download.

---

## 11. Security Requirements (NFR5)

1. Passwords hashed with `pbkdf2:sha256` (≥ 600 000 iterations) and a per-user salt. Never log or return password material.
2. Sessions: `HttpOnly`, `Secure`, `SameSite=Lax` cookies; idle timeout 30 min; absolute timeout 12 h.
3. CSRF protection on all state-changing UI requests.
4. RBAC enforced **server-side** with a `@role_required("ADMIN")` decorator on every admin route. UI hiding is cosmetic only, never the control.
5. All queries via SQLAlchemy parameter binding — no string-built SQL anywhere.
6. Output encoding: Jinja autoescaping on; raw log messages rendered as text content, **never** with `|safe` or `innerHTML`. Logs are attacker-controlled input — treat every field as hostile.
7. Rate-limit login (5 attempts / 15 min / account) and ingestion (per source, configurable, default 500 req/min).
8. Ingest tokens: 32 bytes from `secrets.token_urlsafe`, stored hashed, shown to the admin once.
9. Security headers: `Content-Security-Policy` (no inline scripts — use external JS files and nonces if needed), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`.
10. Application's own audit log written for login, logout, failed login, rule change, source change, user change.
11. HTTPS assumed to be terminated by a reverse proxy in production; document the nginx config.

---

## 12. Performance Requirements

| Ref | Requirement | How to verify |
|---|---|---|
| NFR1 | Ingest → visible on dashboard ≤ 2 s at normal load | `tools/load_test.py` stamps a UUID into a generated log, the client records receipt time, script reports p50/p95/p99 |
| NFR2 | Sustain ≥ 100 events/s with zero loss | generator sends 100 eps for 10 min; assert `count(events) == count(sent)` |
| NFR4 | No loss during transient DB failure | stop the DB for 30 s mid-run; queued events must flush on recovery |

Optimisations expected: batch commits, `execute_many` inserts, DB indexes as specified, coalesced socket emits, precompiled rule regexes, rule cache.

---

## 13. Testing Requirements

- **Unit** — every parser against ≥ 3 real-world sample lines plus malformed input; every DSL operator; the scoring function against a table of `(matched_rules, modifiers) → expected score, expected priority`; the correlator's window pruning.
- **Integration** — POST to `/api/v1/ingest` and assert the event lands in the DB with the correct priority; full incident life cycle through the API including rejection of illegal transitions.
- **Security** — anonymous access to every protected route returns 401/302; an ANALYST calling admin routes returns 403; a stored-XSS payload in a log message renders escaped.
- **Real-time** — SocketIO test client receives `event:new` after ingestion.
- **Performance** — as Section 12.
- **Coverage target:** ≥ 80 % on `app/parsers`, `app/triage`, `app/api`.

Provide `tools/log_generator.py` with modes: `--benign`, `--brute-force`, `--port-scan`, `--traversal`, `--sqli`, `--mixed`, and `--rate <eps> --duration <s>`. This is what produces the evaluation data — it must generate a **ground-truth CSV** alongside the logs (which lines are attacks) so precision/recall of the triage engine can be computed.

---

## 14. Build Order (follow these sprints in order)

**Sprint 1 — Foundation**
Project scaffold, `create_app()`, config classes, Docker Compose (app + postgres), all SQLAlchemy models, initial Alembic migration, seed script for users, login/logout, RBAC decorator, base template and design tokens.
*Done when:* an admin can log in, see an empty shell, and log out; `pytest` green.

**Sprint 2 — Ingestion**
`RawQueue` with disk spill, UDP + TCP syslog listeners, `POST /api/v1/ingest` with token auth and rate limiting, source management API + admin UI, `last_seen_at` tracking.
*Done when:* `logger -n localhost -P 5514 "test"` results in a raw record reaching the queue and a counter incrementing.

**Sprint 3 — Parsing**
Parser ABC, `NormalisedEvent`, six parsers, format registry, dead-letter queue, worker threads persisting events, event list/detail API and a basic events table page.
*Done when:* sample log files in `seeds/sample_logs/` are ingested and correctly normalised, with parser unit tests green.

**Sprint 4 — Triage**
Condition DSL evaluator, correlator, modifiers, scoring, thresholds, rule CRUD API + admin UI + rule tester, seeded default rules, auto-incident creation for CRITICAL.
*Done when:* the generator's brute-force mode produces a CRITICAL event and an auto-created incident.

**Sprint 5 — Real-time dashboard**
SocketIO namespace, rooms, emit helpers, coalescing, stats endpoints, dashboard page with KPI cards, charts, live feed, pause/resume, toasts, alert queue page with filters and bulk actions.
*Done when:* two browsers open the dashboard and both see events appear within 2 s of ingestion.

**Sprint 6 — Incident workflow and reporting**
Transition engine with server-side validation, assignment, comments, event linking, audit timeline, incident detail and list pages, reports (CSV + PDF), full test suite, load test, README/run docs.
*Done when:* every FR in Section 15 passes its acceptance check.

---

## 15. Acceptance Criteria (traceability matrix)

| Req | Statement | Acceptance check |
|---|---|---|
| FR1 | Receive logs via syslog and REST | Send via both channels; both appear as events |
| FR2 | Parse & normalise to common schema | Each supported format yields populated normalised fields |
| FR3 | Evaluate events against configurable rules | Disabling a rule in admin stops it contributing within 30 s |
| FR4 | Score and assign one of five priorities | Scoring unit-test table passes |
| FR5 | Persist events, incidents, user actions | Records survive restart |
| FR6 | Real-time dashboard with throughput, distribution, top sources, live feed | All four widgets update live |
| FR7 | Prioritised, filterable alert queue | Each filter narrows results correctly; sort is by score DESC |
| FR8 | Notify on HIGH/CRITICAL | Toast + socket event fires |
| FR9 | Acknowledge an alert, create an incident from it | Incident references the originating event |
| FR10 | Assign, comment, escalate, resolve, close | All transitions work; illegal ones return 409 |
| FR11 | Auditable, attributed, time-stamped history | Timeline shows every action with actor and time; no edit/delete path exists |
| FR12 | Authentication and role-based access | Anonymous → 401/redirect; analyst → 403 on admin routes |
| FR13 | Admin CRUD for rules and sources | Create/edit/enable/disable all function |
| FR14 | Summary reports for a period | CSV and PDF download with correct totals |
| NFR1 | ≤ 2 s ingest-to-display | p95 latency from load test < 2000 ms |
| NFR2 | ≥ 100 eps, no loss | sent count == stored count |
| NFR3 | Usable without training | New user finds the highest-priority open incident in ≤ 3 clicks |
| NFR4 | No loss during transient failure | DB-outage test flushes on recovery |
| NFR5 | Security controls | Section 11 checklist all pass |
| NFR6 | Modular | Adding a parser touches only `parsers/` + registry |
| NFR7 | Portable | `docker compose up` works on Linux and Windows |

---

## 16. Configuration (`.env.example`)

```ini
FLASK_ENV=development
SECRET_KEY=change-me-to-32-random-bytes
DATABASE_URL=postgresql+psycopg://sentry:sentry@db:5432/sentrylite
# DATABASE_URL=sqlite:///instance/sentrylite.db

SYSLOG_UDP_PORT=5514
SYSLOG_TCP_PORT=5514
SYSLOG_BIND=0.0.0.0

TRIAGE_WORKERS=4
RAW_QUEUE_MAXSIZE=100000
SPILL_DIR=./instance/spill

THRESHOLD_CRITICAL=90
THRESHOLD_HIGH=65
THRESHOLD_MEDIUM=40
THRESHOLD_LOW=15
SCORE_CEILING=200

WORKING_HOURS_START=08:00
WORKING_HOURS_END=18:00
WORKING_DAYS=MON,TUE,WED,THU,FRI
OFF_HOURS_BONUS=10

REPEAT_WINDOW_SECONDS=120
REPEAT_LIMIT=10
REPEAT_BONUS=20

INTERNAL_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
CORRELATOR_MAX_KEYS=50000

SESSION_IDLE_MINUTES=30
LOGIN_MAX_ATTEMPTS=5
INGEST_RATE_LIMIT_PER_MIN=500
SOURCE_SILENT_MINUTES=15
```

---

## 17. Running the System

```bash
# Development
git clone <repo> && cd sentrylite
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then edit SECRET_KEY
flask db upgrade
python -m seeds.seed_users      # creates admin/admin (forced change on first login)
python -m seeds.seed_rules
python run.py                                         # http://localhost:5000

# Generate test traffic
python tools/log_generator.py --mode mixed --rate 20 --duration 120 --target localhost:5514

# Measure performance
python tools/load_test.py --rate 100 --duration 600

# Docker
docker compose up --build
```

---

## 18. Deliverables Checklist

- [ ] Running application meeting every item in Section 15
- [ ] `requirements.txt` with pinned versions
- [ ] Alembic migrations
- [ ] Seed scripts (users, rules, sample logs, critical assets)
- [ ] `tools/log_generator.py` with ground-truth output
- [ ] `tools/load_test.py` producing a latency/throughput report
- [ ] Test suite with ≥ 80 % coverage on core modules, plus a coverage report
- [ ] Dockerfile + docker-compose.yml
- [ ] `DECISIONS.md` recording any judgement calls
- [ ] Screenshots of all screens (for the project report's Chapter Four)
- [ ] A `RESULTS.md` containing: latency percentiles, sustained throughput, and precision/recall of the triage engine against the generator's ground truth

---

## 19. Notes for the Implementing AI

1. **Explainability is a feature.** Every score must be reconstructable from `matched_rules` + `modifiers_applied`. An analyst who cannot see why something scored 92 will not trust the tool — and untrusted tools recreate the alert-fatigue problem this project exists to solve.
2. **Treat log content as hostile.** It is attacker-controlled by definition. Escape on output, never interpolate into SQL or HTML.
3. **Never block the ingestion path.** Accept, enqueue, return. All parsing and scoring happens in workers.
4. **Prefer boring, readable code.** This is an academic project that will be read and defended; clarity beats cleverness. Docstrings on every module and public function.
5. **Commit per sprint**, with a working, demonstrable increment at each sprint boundary.
