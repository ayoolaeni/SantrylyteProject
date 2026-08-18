# SentryLite — Live Demo / Presentation Script

A step-by-step walkthrough that touches every major feature, in an order that tells
a story: *"here's how an attack gets noticed, triaged, and resolved."* Each step
says what to do, what you should see, and what to say. Total time: ~12–15 minutes.

## Before you present

**Use a fresh database** so the numbers on screen make sense to your audience (no
leftover test data from earlier runs):

```powershell
# stop the server first (Ctrl+C) if it's running
Remove-Item instance\sentrylite.db -ErrorAction SilentlyContinue
$env:FLASK_APP = "app:create_app"
flask db upgrade
python -m seeds.seed_users
python -m seeds.seed_rules
python -m seeds.seed_assets
python run.py
```

Open **two terminals**: one running the server (leave it running throughout), one
free for sending demo traffic. Open your browser to **http://localhost:5000**.
Consider a second browser window (or an incognito/private window) logged in as a
different role for the RBAC part.

---

## Part 1 — Login & first impressions (1 min)

1. Go to `http://localhost:5000` → you're redirected to the login page.
2. Log in as `admin` / `admin`.
3. You're forced to a **change password** screen — say: *"passwords are pbkdf2-hashed
   with 600,000 iterations, and default accounts force a change on first login."*
   Set a new password (anything ≥8 characters), e.g. `AdminPass123!`.
4. You land on the **Dashboard** — empty right now. KPI cards, a volume chart, a
   priority-distribution chart, a top-sources chart, and a live event feed with a
   pause/resume toggle.

*Talking point:* everything on this page is fed by a WebSocket connection
(`/live` namespace) — nothing here polls.

---

## Part 2 — Configure a log source (1–2 min)

1. Sidebar → **Admin → Sources**.
2. Create a source: name `demo-source`, host identifier `127.0.0.1`, type `AUTH_LOG`.
3. The ingest token is shown **once** — copy it now. Say: *"tokens are stored as a
   SHA-256 hash server-side — this is the only time it's ever shown in plaintext."*

You'll also want a source for the mixed-traffic demo later:

4. Create a second source: name `mixed-source`, host `127.0.0.1`, type `JSON_GENERIC`.
   Copy its token too.

*Talking point:* also show **Admin → Rules** briefly — 12 default rules, each with a
weight, category, and enable/disable toggle. Point out the **Test** button: paste
`{"event_type": "AUTH_FAILURE"}` and show it reports which rule matches and its
weight — *"this is how an admin sanity-checks a rule before enabling it against live
traffic."*

---

## Part 3 — Real-time ingestion (3 min)

In your second terminal:

```powershell
python tools\log_generator.py --mode mixed --rate 10 --duration 20 --target localhost:5514
```

Switch to the browser, on the **Dashboard**:

- The **live event feed** fills in as events arrive (batched every 250ms).
- The **volume chart** and **priority distribution** update within a few seconds.
- Point out the **priority pills** — colour is always paired with a text label and a
  distinct shape, never colour alone (accessibility, WCAG AA).

*Talking point:* *"that traffic went out over UDP syslog on port 5514, exactly like a
real log shipper would send it. Ingestion never blocks — it's enqueued and processed
by a pool of worker threads; if the queue ever fills up, messages spill to disk and
retry automatically rather than being lost."*

---

## Part 4 — Watch an attack get caught (2–3 min)

This is the centrepiece. Run a brute-force burst:

```powershell
python tools\log_generator.py --mode brute-force --rate 20 --duration 1 --target localhost:5514
```

Within ~1–2 seconds you should see:

- A **toast notification** pop up top-right ("CRITICAL alert...").
- (If browser notifications were granted) a native OS notification.
- The **Open Critical** KPI card increments.

Click through to **Alerts**, or **Incidents**, and open the newly created incident
(`INC-2026-0000xx`).

*Talking point — this is the explainability feature, don't skip it:* point at the
**"Why CRITICAL (score N)?"** section. *"Every score is reconstructible — here are
the exact rules that matched and their weights, and any contextual modifiers
(critical asset, off-hours, repeat offender) that were applied. An analyst never has
to trust a black box."*

Also point out the **raw message** shown verbatim in a monospace block — *"log
content is attacker-controlled and untrusted; it's rendered as plain text, never
interpreted as HTML."*

---

## Part 5 — Work the alert queue (2 min)

1. Sidebar → **Alert Queue**.
2. Show the sticky filter bar: filter by priority, search free-text, filter by
   status. Note the URL updates as you filter — *"shareable, bookmarkable views."*
3. Pick a `MEDIUM`/`LOW` event → **Acknowledge** it (status changes inline).
4. Pick another → **Dismiss** it, entering a reason (false positive).
5. Pick a `HIGH` one → **Create Incident** from it → you're taken straight to the new
   incident's detail page.

---

## Part 6 — Run an incident through its lifecycle (2–3 min)

On any open incident detail page:

1. **Acknowledge** it → note the audit timeline entry appears immediately with your
   name and timestamp.
2. **Investigate** it.
3. Try to jump straight to **Closed** — it's not offered; only the states legal from
   `INVESTIGATING` are shown. Say: *"transitions are enforced server-side — even a
   direct API call to an illegal transition gets a 409, this isn't just UI hiding."*
4. **Resolve** it — you're required to enter a resolution summary (try leaving it
   blank first to show the validation).
5. **Close** it.
6. Scroll the **audit timeline** — every single action, who did it, and when.

*Optional:* assign the incident to another user, add a comment, link a related event
by ID — all visible in the timeline.

---

## Part 7 — Reports (1 min)

1. Sidebar → **Reports**. Pick a date range covering today.
2. Show the on-screen summary (MTTA/MTTR, totals by priority/state).
3. Click **Download CSV**, then **Download PDF** — both should download real files.

---

## Part 8 — Role-based access control (1–2 min, optional but strong finish)

In your second browser window:

1. Log in as `analyst` / `analyst123` (also forces a password change).
2. Try to browse directly to `http://localhost:5000/admin/rules` → **403 Forbidden**.
3. Show the analyst *can* acknowledge alerts and work incidents, but the **Admin**
   section isn't even in their sidebar.

*Talking point:* *"three roles — Administrator, Analyst, and read-only Viewer — and
the check happens on every request server-side. Hiding the Admin link in the sidebar
is just convenience; the actual enforcement is a role check in front of every
route."*

---

## If something goes wrong mid-demo

- **Nothing appearing after `log_generator.py`?** Check the source's `host_identifier`
  matches where you're sending from (`127.0.0.1` if running the script locally
  against `localhost:5514`).
- **"Invalid token" from `log_generator.py`?** It doesn't use a token — that's only
  for `POST /api/v1/ingest`. Syslog UDP/TCP is matched by sender IP, not a token.
- **Want to reset mid-demo without restarting?** Just re-run the traffic generator
  commands from Part 3/4 — new events keep appending, nothing needs to restart.
- **Full reset between rehearsals:** repeat the "Before you present" block at the top.

## Appendix — one-shot script

If you'd rather run the whole traffic sequence unattended while you talk over it:

```powershell
python tools\log_generator.py --mode benign --rate 5 --duration 5 --target localhost:5514
python tools\log_generator.py --mode port-scan --rate 15 --duration 2 --target localhost:5514
python tools\log_generator.py --mode traversal --rate 5 --duration 3 --target localhost:5514
python tools\log_generator.py --mode sqli --rate 5 --duration 3 --target localhost:5514
python tools\log_generator.py --mode brute-force --rate 20 --duration 1 --target localhost:5514
```

Run it, then switch to the dashboard — by the time you get there, the live feed,
charts, and at least one auto-created CRITICAL incident will already be waiting.
