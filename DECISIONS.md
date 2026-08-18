# DECISIONS.md

Judgement calls made while implementing SentryLite from the README specification,
where the spec left a detail unstated or where a real bug surfaced during build-out
that required a design decision to fix properly. Ordered roughly by area.

## Repository layout
- This repository's root **is** `sentrylite/` from the spec's §4 layout — there is no
  extra nested `sentrylite/` folder. `README (1).md` (the original spec file) is left
  untouched at the root as the source specification.

## Data model
- `event.event_id`, `incident_action.action_id` and the (spec-unlisted, added by us)
  `audit_log.audit_id` are declared as
  `BigInteger().with_variant(Integer, "sqlite")`, not a bare `BigInteger`. SQLite's
  rowid-alias autoincrement only activates for a column declared as exactly
  `INTEGER PRIMARY KEY` — a bare `BIGINT PRIMARY KEY` silently *never autoincrements*
  under SQLite, so every insert failed with `NOT NULL constraint failed` until this
  was added. Postgres (prod) still gets a real `BIGINT` column; only the SQLite
  dev/test dialect gets the substitution.
- Added an `AuditLog` model (`app/models/audit_log.py`), not in the spec's §5 table
  list, to satisfy NFR5.10 ("application's own audit log written for login, logout,
  failed login, rule change, source change, user change") — distinct from
  `incident_action`, which audits the incident workflow only.
- A `system` user (`role=ADMIN`, `is_active=False`, unusable random password) is
  auto-created the first time the triage engine needs to attribute an
  auto-created-incident's `CREATED` action, since `incident_action.user_id` is
  `NOT NULL` and the engine itself has no logged-in actor.
- `DELETE /api/v1/users/<id>` soft-deletes (`is_active=false`) rather than removing
  the row, since incidents/audit rows carry FK references to `user_id` that must
  survive account deactivation.

## Triage engine / condition DSL
- Rule #6 ("malformed/oversized request", §6.3) has no dedicated DSL operator for
  string length, so it's expressed as `raw_message regex "^.{4097,}"` (matches a line
  longer than 4096 characters) rather than adding a bespoke `length` operator outside
  the spec's fixed operator list.
- Rule #11 ("account created outside change window") only checks
  `event_type == ACCOUNT_CREATED`; "outside working hours" isn't re-implemented as a
  rule-level condition since the DSL has no time-of-day operator — it's already
  covered by the global off-hours scoring modifier (§6.1), which applies to every
  event including this one.
- Rule #8's "protected path" check matches against `message` (not `http_path`, which
  `FILE_ACCESS` events don't populate) since our `NormalisedEvent` has no dedicated
  file-path field.
- The `sequence` correlation type's schema (used by rule #2, "successful login after
  failures") isn't fully specified in §6.2's example. Implemented as
  `{"type": "sequence", "group_by": ..., "first": <condition>, "min_count": N,
  "window_seconds": S}` — the rule's own top-level `all`/`any` condition is treated as
  the "second" leg (the current event), and `first` is evaluated and recorded into
  correlator state on *every* event regardless of whether the base condition matches,
  so a run of `AUTH_FAILURE` events is tracked even though the rule's own base
  condition only matches on `AUTH_SUCCESS`.
- The rule cache (`app/triage/engine.py::_rule_cache`) and critical-asset cache
  (`app/triage/modifiers.py::_asset_cache`) store **plain dataclass snapshots**
  (`_RuleView`, `_AssetView`), not live SQLAlchemy ORM objects. A module-level TTL
  cache outlives any single request, while Flask-SQLAlchemy tears down its scoped
  session at the end of every request/app-context — a cached *ORM instance* becomes
  detached the moment that happens, and the next cache hit from a later request raised
  `DetachedInstanceError` the instant a lazy attribute was touched. Caching plain data
  sidesteps the session lifecycle entirely.

## Ingestion / concurrency
- SQLite (dev/test) is genuinely multi-writer in this app (up to `TRIAGE_WORKERS`
  worker threads plus every request handler can commit), but SQLite only ever allows
  one writer at a time. The fix (`app/__init__.py::_configure_sqlite_concurrency`,
  Postgres-exempt) is two-layered:
  1. `PRAGMA journal_mode=WAL` + `PRAGMA busy_timeout=30000` on every SQLite connection.
  2. A process-wide `threading.Lock`, acquired lazily on a connection's *first* write
     statement (INSERT/UPDATE/DELETE) and released on commit/rollback — not acquired
     for read-only transactions. This was deliberately not "lock every transaction":
     an earlier version that locked at `Engine.begin()` (i.e. every transaction, reads
     included) serialized the entire app and inflated ingest latency into the tens of
     seconds under load. Serializing only the actual writers keeps every `GET` (the
     dashboard, the alert queue, the login token check) fully concurrent while still
     eliminating "database is locked" errors between writers. Verified live: 3000
     events at 100 eps sustained, zero loss, p95 ingest-to-visible latency 734ms
     (see RESULTS.md).
  3. Under eventlet specifically, a *blocked* SQLite C call doesn't yield the event
     loop the way patched I/O does — so relying on `busy_timeout` alone to queue
     contending writers can stall the whole process for the timeout's duration rather
     than degrading gracefully. The application-level lock avoids ever reaching that
     C-level wait in the first place.
- A syslog UDP/TCP sender is matched to a `LogSource` by `host_identifier == sender IP`
  (`host_hint` in `RawQueue`). An unmatched sender's events are still parsed and
  persisted (with `source_id = NULL`) rather than dropped — the spec doesn't say to
  reject unregistered senders, and dropping them silently would be worse for an
  analyst trying to see what's actually arriving.
- `RawQueue`'s disk spill format is newline-delimited JSON
  (`{source_id, raw_message, received_at, host_hint}` per line) under
  `SPILL_DIR/spill.ndjson`; the dead-letter queue for genuinely unparseable lines is a
  separate `SPILL_DIR/dead_letter.ndjson`.
- Worker commit batching (§3.1, "up to 50 events or every 500ms") is implemented with
  the raw pre-parse item retained alongside each batch. If the batch commit itself
  fails (e.g. a transient DB outage), the whole batch's *raw* messages are re-spilled
  to disk (not the already-normalised/scored objects) and retried once the queue
  drains again — this is what makes NFR4 (no loss during a transient DB outage) hold.

## API
- Session-cookie-authenticated API routes (everything except `/api/v1/ingest`) keep
  CSRF protection; only the bearer-token ingest endpoint is exempted, since external
  log shippers have no session/CSRF token to present.
- Ingest tokens are stored as `sha256(token)` (indexed, O(1) lookup), not a slow
  password-style hash — they're 256-bit random tokens (`secrets.token_urlsafe(32)`),
  not user-chosen secrets, so a fast, reversible-only-by-brute-force hash is the right
  trade-off for a value that must be looked up on every ingest request.
- `GET /api/v1/incidents/<id_or_reference>` (and the mutation routes) accept either
  the numeric `incident_id` or the human-readable `reference` (`INC-2026-000123`) —
  the spec's REST examples use a bare `<id>` placeholder but the UI's own incident
  detail page necessarily routes by `reference`.
- The alert-queue "source" filter has no dedicated non-admin "list sources" endpoint,
  since §8.5 scopes `GET /api/v1/sources` to `ADMIN` only. The frontend instead derives
  the source picker from `/api/v1/stats/top-sources`, which is available to every role.

## Frontend
- No bundler: all first-party JS is hand-written ES6 modules loaded via
  `<script type="module">`; Chart.js and socket.io-client are vendored as their
  prebuilt UMD/minified bundles under `app/static/js/vendor/` (downloaded once, not
  fetched from a CDN at runtime) so the app has no third-party runtime dependency and
  keeps working under the strict `script-src 'self'` CSP.
- Every place that renders attacker-controlled content (event `message`,
  `raw_message`, etc.) goes through `ui.js`'s `el()` helper, which only ever sets
  `textContent` — never `innerHTML` — so there is no code path where a stored-XSS
  payload in a log line can execute (NFR5.6).

## Testing
- `tests/conftest.py`'s `app` fixture holds one Flask app context open for the whole
  test (the common Flask-SQLAlchemy testing pattern, needed so fixtures/test bodies
  can touch `db.session` without their own `with app.app_context()`). That pattern has
  a sharp edge: Flask's `RequestContext.push()` reuses an already-active app context
  for the same Flask app rather than pushing a fresh one, and flask-login caches
  `current_user` on `flask.g` — which lives on the app context. Left alone, every
  test-client request in a test shared one `g`, so whichever user logged in *first*
  silently "stuck" as `current_user` for every later request in that test, even ones
  sent by a different, separately-logged-in test client. `_IsolatedClient` in
  conftest.py works around this by hiding the ambient app context (via the raw
  `flask.globals._cv_app` contextvar, not `AppContext.pop()`, which would additionally
  fire Flask-SQLAlchemy's teardown and detach every ORM object the test already holds)
  for the duration of each request, forcing Flask to push a genuinely fresh context.
- A related, separate bug this surfaced: `@socketio.on(...)` decorators in
  `app/realtime/events.py` only *execute* once, because Python caches module imports —
  so a second `create_app()` call in the same process (every test; also any real
  multi-app scenario) left its brand-new `socketio.server` with **no handlers
  registered at all**, silently rejecting every connection at the transport layer
  before any application code ran. Fixed by registering handlers via an explicit
  `register_handlers()` function called from `create_app()` every time, instead of
  relying on import-time decorator side effects.
- Coverage target (≥80% on `app/parsers`, `app/triage`, `app/api`) is met in aggregate
  (86% combined); individual admin CRUD files vary 88–100%, `app/api/helpers.py` and
  `app/api/incidents.py` are the lowest at 65% and 72% respectively (their untested
  lines are mostly parameter-validation edge cases already covered by RBAC-focused
  tests exercising the success path).

## Ops / deliverables
- `docker-compose.yml`'s app command chains `flask db upgrade` and all three seed
  scripts before `python run.py`, so `docker compose up --build` alone is sufficient
  for a first run (matches §17's simplicity).
- **Docker build — since verified.** An earlier pass through this section noted the
  Docker build hadn't been runtime-tested (no daemon available at the time). Once
  Docker Desktop was available it was: `docker compose up -d --build --wait` builds
  the app image, starts Postgres, runs `flask db upgrade` and all three seed scripts,
  and serves the app — confirmed by repeating the login → change-password → create-source
  → syslog-brute-force → auto-created-CRITICAL-incident flow from RESULTS.md against
  the containerised stack, end to end, successfully.
- Added a `healthcheck` to the `app` service (hits `/auth/login` from inside the
  container) so `docker compose up --wait` — and the `Start SentryLite.bat` script —
  can block until the app is actually ready to receive traffic, not just until the
  process has started.
- `Start SentryLite.bat` / `Stop SentryLite.bat` (repo root) exist purely for a
  non-technical audience (e.g. handing this to a client): double-click to build/start
  and open the browser automatically, double-click the other to stop. They're a thin
  wrapper around the `docker compose` commands above with a friendly message if
  Docker Desktop isn't running yet. `HOW TO RUN.txt` is the plain-language
  instructions to go with them.
- `ProdConfig.SESSION_COOKIE_SECURE` defaults to `True` (HTTPS assumed, per §11.11)
  but honors a `SESSION_COOKIE_SECURE=false` env override — needed to demo
  `docker compose up` locally over plain HTTP without an nginx/TLS front end; a real
  deployment should leave it at its secure default and terminate TLS as shown in
  `docs/nginx.conf.example`.
