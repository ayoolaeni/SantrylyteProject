# SentryLite

SentryLite is a lightweight, self-hostable security incident response and log
triage dashboard. It ingests logs from multiple sources in real time, normalises
them into one event schema, scores and prioritises them with a configurable rule
engine, streams triaged events to a live browser dashboard, and manages the
resulting incidents through a structured response workflow — without needing a
commercial SIEM.

The full build specification this was implemented from is [`README (1).md`](README%20(1).md).
Judgement calls made along the way (where the spec left something unstated, or a
real bug required a design decision) are in [`DECISIONS.md`](DECISIONS.md). Measured
performance and detection accuracy are in [`RESULTS.md`](RESULTS.md). Presenting or
demoing this? [`DEMO.md`](DEMO.md) is a step-by-step script that walks through every
major feature in about 12 minutes.

## What it does

- **Ingests logs** two ways: a syslog listener (UDP + TCP, port 5514 by default) for
  anything that can `logger`/forward syslog, and an authenticated REST endpoint
  (`POST /api/v1/ingest`) for anything that can make an HTTP request.
- **Parses** seven log formats — RFC 3164 and RFC 5424 syslog, Linux `auth.log`,
  nginx/Apache combined access logs, generic JSON application logs, and
  JSON-exported Windows Security events — auto-detecting the format when a source
  doesn't declare one.
- **Scores every event** against a set of weighted rules (12 are seeded by default:
  brute force, privilege escalation, port scanning, directory traversal, SQL
  injection, and more), plus contextual modifiers for critical assets, off-hours
  activity, and repeat offenders. Each event gets a `severity_score` and a priority
  band (`INFORMATIONAL` → `CRITICAL`). A `CRITICAL` score auto-creates an incident.
- **Streams everything live** over WebSocket to a browser dashboard: KPI cards,
  event-volume and priority-distribution charts, a live event feed, and toast/browser
  notifications on high-severity alerts.
- **Manages the incident lifecycle**: New → Acknowledged → Investigating →
  (Escalated | False Positive | Resolved) → Closed, with assignment, comments, linked
  events, and a full append-only audit timeline. Every transition is enforced
  server-side.
- **Lets admins tune the system without redeploying**: rules (with a "test this rule
  against a sample event" tool), log sources (with per-source ingest tokens), critical
  assets, and users, all from the admin UI.
- **Reports**: a date-ranged incident summary (totals by priority/state, MTTA/MTTR,
  top triggered rules, top source IPs) exportable as JSON, CSV, or PDF.

## How it works

```
log sources ──(syslog UDP/TCP or REST)──▶ RawQueue (disk-backed, never blocks)
                                              │
                                    worker threads: parse → triage → persist
                                              │
                              ┌───────────────┴───────────────┐
                              ▼                                ▼
                         PostgreSQL/SQLite                 SocketIO (/live)
                    (events, incidents, rules,           → browser dashboard,
                     users, audit trail)                   alert queue, toasts
```

- **Ingestion never blocks**: a syslog datagram or REST POST is enqueued and the
  connection returns immediately; all parsing, scoring, and persistence happens in a
  pool of worker threads (`TRIAGE_WORKERS`, default 4) that commit in small batches.
  If the queue fills up or the database is briefly unreachable, raw messages spill to
  disk and are retried automatically once things recover — nothing is silently
  dropped.
- **Every score is explainable**: an event's `matched_rules` and `modifiers_applied`
  are stored alongside it and shown in the incident detail view, so an analyst can
  always see exactly why something scored what it did.
- **Rules are data, not code**: each rule's condition is a small JSON expression tree
  (field/operator/value, combined with `all`/`any`/`none`, optionally with a
  correlation clause for "N times in M seconds" patterns). Nothing is ever `eval()`'d.
  Enabling, disabling, or reweighting a rule from the admin UI takes effect for new
  events within 30 seconds, no restart required.
- **Security is server-enforced**: role checks (Admin / Analyst / Viewer), CSRF
  protection on session-authenticated routes, hashed passwords and ingest tokens,
  account lockout after repeated failed logins, and security headers are all applied
  in the backend — the UI hiding a button is cosmetic, never the actual control.

See [`DECISIONS.md`](DECISIONS.md) for the more interesting internals: why SQLite
needed a custom write-serialisation fix under concurrent load, why the rule/asset
caches store plain data instead of live database objects, and a couple of subtle
bugs (a Flask test-context leak, a SocketIO handler-registration bug) that were
found and fixed while building this out.

## Requirements

- Python 3.11+
- SQLite (bundled with Python — no setup needed) for development, or PostgreSQL 15
  for production
- (Optional) Docker + Docker Compose, if you'd rather not set up Python locally

## Running it locally

```bash
git clone <repo> && cd sentrylite   # or just cd into this folder if already cloned
python -m venv .venv
.venv\Scripts\activate              # Windows
# source .venv/bin/activate         # macOS/Linux

pip install -r requirements.txt
copy .env.example .env              # Windows: copy | macOS/Linux: cp
```

Open `.env` and set `SECRET_KEY` to a random 32-byte string. The default
`DATABASE_URL` points at a local SQLite file under `instance/` — nothing else to
configure to get started.

```bash
# Create the database schema
set FLASK_APP=app:create_app         # Windows (cmd)
$env:FLASK_APP="app:create_app"      # Windows (PowerShell)
export FLASK_APP=app:create_app      # macOS/Linux
flask db upgrade

# Seed an admin account, the default rules, and two example critical assets
python -m seeds.seed_users
python -m seeds.seed_rules
python -m seeds.seed_assets

# Run it
python run.py
```

The app is now at **http://localhost:5000**. Log in with:

| Username | Password | Role | Note |
|---|---|---|---|
| `admin` | `admin` | Administrator | forced password change on first login |
| `analyst` | `analyst123` | Analyst | forced password change on first login |

To actually see something on the dashboard, register a log source (**Admin →
Sources**), which gives you an ingest token, then either point a syslog sender at
`localhost:5514`, or generate synthetic traffic:

```bash
python tools/log_generator.py --mode mixed --rate 15 --duration 30 --target localhost:5514
```

Try `--mode brute-force` to watch a CRITICAL incident get auto-created in real time
on the dashboard.

## Running it with Docker

**On Windows, with nothing installed but Docker Desktop**, just double-click
`Start SentryLite.bat` — it builds and starts everything, waits until it's actually
ready, and opens your browser to it automatically. `Stop SentryLite.bat` shuts it
down (your data is kept in a Docker volume between runs). See
[`HOW TO RUN.txt`](HOW%20TO%20RUN.txt) for the no-technical-background version of
these instructions — that's the file to hand to a client.

From a terminal, the equivalent is:

```bash
docker compose up -d --build --wait
```

This builds the app image, starts a PostgreSQL 15 container, runs migrations and all
three seed scripts automatically, and serves the app on **http://localhost:5000**
(syslog on `5514/udp` and `5514/tcp`). `--wait` blocks until both containers report
healthy, so the command doesn't return until it's actually safe to open the browser.
Log in with the same `admin`/`admin` credentials as above.

```bash
docker compose down    # stop it; add -v to also wipe the database volume
```

Verified end-to-end (build → migrate → seed → login → syslog ingestion → auto-created
incident) — see the Docker section of `DECISIONS.md` for what that check covered.

For a real deployment, put SentryLite behind a TLS-terminating reverse proxy — see
[`docs/nginx.conf.example`](docs/nginx.conf.example) — and leave `SESSION_COOKIE_SECURE`
at its default (`true` under `FLASK_ENV=production`).

## Generating test traffic / measuring performance

```bash
# Synthetic benign + attack traffic, with a ground-truth CSV for precision/recall
python tools/log_generator.py --mode mixed --rate 20 --duration 120 --target localhost:5514

# Latency (ingest → visible) and sustained-throughput measurement against a running server
python tools/load_test.py --rate 100 --duration 600 --ingest-token <token> \
    --username admin --password <password>
```

`tools/log_generator.py` supports `--mode benign|brute-force|port-scan|traversal|sqli|mixed`.
See [`RESULTS.md`](RESULTS.md) for real numbers from both tools.

## Running the tests

```bash
pytest -q
# with coverage:
pytest -q --cov=app.parsers --cov=app.triage --cov=app.api --cov-report=term-missing
```

133 tests covering parsers, the triage engine and condition DSL, the correlator,
the full REST API, RBAC, and the real-time SocketIO layer. 86% coverage across
`app/parsers`, `app/triage`, and `app/api`.

## Project layout

```
app/
├── ingestion/     syslog listeners, the disk-backed RawQueue, worker threads
├── parsers/       one file per log format + a registry that auto-detects format
├── triage/        the scoring engine, condition DSL, and sliding-window correlator
├── api/           the REST API (events, incidents, rules, sources, users, stats, reports)
├── realtime/      SocketIO handlers and emit helpers for the /live namespace
├── security/      RBAC decorator and the security audit log
├── models/        SQLAlchemy models
├── views/         page-shell routes (the actual data comes from app/api via JS)
├── static/js/     hand-written ES6 modules (no build step) + vendored Chart.js/socket.io-client
└── templates/     Jinja page shells
seeds/             seed scripts + sample log files for each supported format
tools/             log_generator.py and load_test.py
tests/             pytest suite
```

## Configuration

All runtime settings (triage thresholds, working hours, correlation windows, queue
sizes, rate limits, session timeouts, etc.) are environment variables — see
[`.env.example`](.env.example) for the full list with defaults.
