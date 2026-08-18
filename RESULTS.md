# RESULTS.md

Measurements taken against a live instance (`python run.py`-equivalent, SQLite dev
database, default seeded rules, single process, Windows 11 host) using
`tools/load_test.py` and `tools/log_generator.py`. Reproduction commands are given
under each section.

## NFR1 — ingest-to-visible latency

`tools/load_test.py` stamps a unique marker into each event's message, sends it via
`POST /api/v1/ingest`, and polls `GET /api/v1/events` **concurrently** (a background
thread, running the whole time sending is happening) until the marker appears,
recording `time_observed - time_sent` per event.

```
python tools/load_test.py --rate 100 --duration 30 --ingest-token <token> \
    --username admin --password <password>
```

| Metric | Value |
|---|---|
| Sent | 3000 |
| Accepted | 3000 |
| Confirmed visible | 3000 |
| Missing | 0 |
| **p50 latency** | **265 ms** |
| **p95 latency** | **734 ms** (target: < 2000 ms) |
| p99 latency | 906 ms |
| min / max | 0 ms / 2625 ms |

**NFR1: PASS.** p95 is well under the 2-second target at the spec's own 100 events/sec
reference load.

Note: `INGEST_RATE_LIMIT_PER_MIN` (default 500/min ≈ 8.3 eps) was raised to 12000 for
this run — at its default the limiter itself would reject most of a 100 eps burst
from a *single* source by design (§11.7), which a real deployment would spread across
multiple registered sources or size the per-source limit for.

## NFR2 — sustained throughput, zero loss

Same run as above: 100 events/sec sustained for 30 seconds (3000 events) with 4
`TRIAGE_WORKERS`. **Sent count == accepted count == confirmed-visible count: 3000 ==
3000 == 3000.**

**NFR2: PASS.**

### A concurrency bug this surfaced (and the fix)

The first attempt at this measurement produced repeated `sqlite3.OperationalError:
database is locked` errors and, briefly, requests that hung for the length of a
30-second busy-timeout — SQLite only ever allows one writer, and this app is
genuinely multi-writer (`TRIAGE_WORKERS` worker threads plus every request handler
can commit). The fix (see `app/__init__.py::_configure_sqlite_concurrency`, and
DECISIONS.md for the full story) serialises only the transactions that actually
write through a single process-wide lock, leaving every read (the dashboard, the
alert queue, every `GET`) fully concurrent. This is SQLite-only and Postgres-exempt —
production doesn't need it.

## Precision / recall of the triage engine

`tools/log_generator.py --mode mixed --rate 15 --duration 20` produced 300 lines
(135 flagged as attacks in its ground-truth CSV: benign, brute-force, port-scan,
directory-traversal and SQLi traffic interleaved) sent over syslog UDP. Every line
was cross-referenced against the resulting `event` row by exact raw-message match.
"Flagged" = triage engine assigned `MEDIUM`, `HIGH` or `CRITICAL` (i.e. it would
appear in the alert queue, as opposed to being filed as background noise).

```
python tools/log_generator.py --mode mixed --rate 15 --duration 20 --target localhost:5514
```

| | Predicted attack | Predicted benign |
|---|---|---|
| **Actual attack** | TP = 92 | FN = 43 |
| **Actual benign** | FP = 0 | TN = 165 |

**Precision: 1.000** — the engine never flagged benign traffic in this run.
**Recall: 0.681** · **F1: 0.811**

Recall by attack type:

| Attack type | Flagged | Total | Why |
|---|---|---|---|
| traversal | 30/30 | 100% | Every line independently matches rule 5 (weight 50 ⇒ MEDIUM on its own). |
| brute-force | 40/45 | 89% | Rule 1 requires **>5** `AUTH_FAILURE` from one IP within 120s (§6.1) — by design, the first 5 lines of each burst score 0 until the threshold is crossed; only the overflow is flagged. |
| port-scan | 15/30 | 50% | Rule 4 requires **>15** distinct ports within 60s — by design, the first 15 distinct ports of a 30-port scan don't yet cross the threshold. |
| sqli | 7/30 | 23% | Rule 9's regex covers 3 known patterns (`union select`, `' or '1'='1`, `sleep(`); only 1 of the generator's 4 SQLi payload templates matches one of them. The other 3 (comment-based auth bypass `admin'--`, encoded `SELECT SLEEP(5)`, etc.) are genuinely uncovered by this rule set. |

**Read honestly**, not as a shortcoming to explain away: two of the four gaps
(brute-force, port-scan) are the *correlation threshold working exactly as specified*
— an analyst doesn't want every single failed login individually flagged, only the
pattern. The real, worth-fixing-in-a-future-iteration gap is SQLi coverage: three
plausible injection techniques aren't in rule 9's pattern list. This is precisely the
kind of blind spot a purely signature-based engine has, and is a reasonable next
rule-tuning target (visible in the admin rules UI's "test rule against sample event"
tool) rather than a defect in the scoring mechanism itself.

10 events also reached `CRITICAL` and auto-created incidents during this run (stacked
rule matches plus the off-hours/repeat-source modifiers pushing a handful of
already-flagged events over the 90-point threshold) — consistent with §6.1's
auto-incident-creation behaviour.

## Test suite

```
pytest -q --cov=app.parsers --cov=app.triage --cov=app.api --cov-report=term-missing
```

- **133 tests, all passing.**
- Coverage: **86%** combined across `app/parsers`, `app/triage`, `app/api` (target:
  ≥80%). Individual files range 65%–100%; the lowest (`app/api/helpers.py` 65%,
  `app/api/incidents.py` 72%) are parameter-validation edge cases not hit by the
  RBAC- and workflow-focused tests that already exercise their success paths.

## Not measured here

- **NFR4** (no data loss during a transient DB outage) is exercised by the
  worker-level retry/re-spill logic (`app/ingestion/worker.py`) and covered by unit
  tests around `RawQueue.put_back`/`drain_spill`, but wasn't re-validated against a
  live Postgres outage in this pass — the mechanism (rollback + re-spill the batch's
  raw messages to disk, drained back onto the queue once commits succeed again) is
  the same one that made the SQLite lock contention above safe to fix without losing
  data.
- Docker build/deploy — see DECISIONS.md; not runnable in the sandbox this was built
  in (no Docker daemon available).
