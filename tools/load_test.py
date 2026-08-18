#!/usr/bin/env python
"""Measures NFR1 (ingest -> visible-on-dashboard latency) and NFR2 (sustained
throughput, zero loss) against a *running* SentryLite server.

Each event's message carries a unique marker; the script records the send time per
marker, then polls the events API (which is what the dashboard itself calls) until
every marker has appeared, computing how long each one actually took to become
visible. Requires an admin/analyst login (to query /api/v1/events) and an ingest
token for an existing, enabled log source (create one first via /admin/sources).

Polling runs concurrently with sending (a background thread), not after it —
otherwise an event sent early in a long run would show a falsely huge "latency"
that's really just "how much longer the script kept sending other events".

Usage:
    python tools/load_test.py --rate 100 --duration 600 --ingest-token <token> \
        --username admin --password admin
"""
import argparse
import json
import re
import statistics
import threading
import time
import uuid
from datetime import datetime, timezone

import requests

CSRF_RE = re.compile(r'name="csrf-token" content="([^"]+)"')
MARKER_RE = re.compile(r"marker=([0-9a-f]{32})")


def login(session, base_url, username, password):
    resp = session.get(f"{base_url}/auth/login")
    resp.raise_for_status()
    match = CSRF_RE.search(resp.text)
    if not match:
        raise RuntimeError("could not find CSRF token on login page")
    csrf_token = match.group(1)

    resp = session.post(
        f"{base_url}/auth/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        allow_redirects=True,
    )
    resp.raise_for_status()
    if "/auth/login" in resp.url:
        raise RuntimeError("login failed — check --username/--password")


class Poller(threading.Thread):
    """Runs concurrently with sending: repeatedly checks /api/v1/events for markers
    that have appeared, recording latency = (moment observed) - (moment sent)."""

    def __init__(self, base_url, session, run_id, poll_interval=0.25):
        super().__init__(daemon=True)
        self.base_url = base_url
        self.session = session
        self.run_id = run_id
        self.poll_interval = poll_interval
        self.lock = threading.Lock()
        self.pending = {}  # marker -> send_time
        self.latencies = {}  # marker -> latency seconds
        self._stop = threading.Event()

    def register_sent(self, marker, send_time):
        with self.lock:
            self.pending[marker] = send_time

    def stop(self):
        self._stop.set()

    def run(self):
        page_size = 200
        while not self._stop.is_set():
            now = time.monotonic()
            with self.lock:
                still_pending = bool(self.pending)
            if still_pending:
                page = 1
                found = {}
                while True:
                    try:
                        resp = self.session.get(
                            f"{self.base_url}/api/v1/events",
                            params={"q": f"run={self.run_id}", "per_page": page_size, "page": page, "sort": "-event_id"},
                            timeout=10,
                        )
                        resp.raise_for_status()
                        body = resp.json()
                    except requests.RequestException:
                        break
                    for event in body["data"]:
                        m = MARKER_RE.search(event.get("message") or "")
                        if m:
                            found[m.group(1)] = now
                    if len(body["data"]) < page_size or page * page_size >= body["total"]:
                        break
                    page += 1

                with self.lock:
                    for marker, observed_at in found.items():
                        send_time = self.pending.pop(marker, None)
                        if send_time is not None and marker not in self.latencies:
                            self.latencies[marker] = observed_at - send_time

            time.sleep(self.poll_interval)

    def wait_for_all(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if not self.pending:
                    break
            time.sleep(0.2)
        with self.lock:
            missing = set(self.pending.keys())
        return dict(self.latencies), missing


def send_events(base_url, ingest_token, run_id, rate, duration, poller):
    """Fire events at ~`rate` eps for `duration` seconds, registering each with `poller`."""
    session = requests.Session()
    headers = {"Authorization": f"Bearer {ingest_token}"}
    interval = 1.0 / rate if rate > 0 else 0
    total = max(1, int(rate * duration))

    accepted = 0
    start = time.monotonic()
    for i in range(total):
        marker = uuid.uuid4().hex
        payload = {
            "event_type": "OTHER",
            "message": f"loadtest run={run_id} marker={marker} seq={i}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        send_time = time.monotonic()
        try:
            resp = session.post(
                f"{base_url}/api/v1/ingest",
                json={"message": json.dumps(payload)},
                headers=headers,
                timeout=5,
            )
            if resp.status_code == 202 and resp.json().get("accepted"):
                poller.register_sent(marker, send_time)
                accepted += 1
        except requests.RequestException as exc:
            print(f"  send error at i={i}: {exc}")

        target_next = start + (i + 1) * interval
        sleep_for = target_next - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)

    elapsed = time.monotonic() - start
    print(f"Sent {total} event(s), {accepted} accepted, in {elapsed:.1f}s (~{total/elapsed:.1f} eps actual)")
    return total, accepted


def report(latencies, missing, total_sent, accepted):
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Sent:      {total_sent}  (accepted: {accepted})")
    print(f"Confirmed visible: {len(latencies)}")
    print(f"Missing (never appeared within timeout): {len(missing)}")
    if latencies:
        values = sorted(v * 1000 for v in latencies.values())  # ms
        p50 = statistics.median(values)
        p95 = values[min(len(values) - 1, int(len(values) * 0.95))]
        p99 = values[min(len(values) - 1, int(len(values) * 0.99))]
        print(f"Latency p50: {p50:.0f} ms")
        print(f"Latency p95: {p95:.0f} ms  (NFR1 target: < 2000 ms)")
        print(f"Latency p99: {p99:.0f} ms")
        print(f"Latency min/max: {values[0]:.0f} / {values[-1]:.0f} ms")
    if missing or accepted != total_sent:
        print("NFR2 (zero loss) FAILED — some events were rejected or never became visible.")
    else:
        print("NFR2 (zero loss): sent count == accepted count == confirmed-visible count. PASS")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://localhost:5000")
    parser.add_argument("--ingest-token", required=True, help="bearer token for an enabled log source")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--rate", type=float, default=100.0, help="events per second (NFR2 default: 100)")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds")
    parser.add_argument("--poll-timeout", type=float, default=60.0, help="seconds to wait for stragglers to appear")
    args = parser.parse_args()

    run_id = uuid.uuid4().hex[:8]
    print(f"Load test run_id={run_id}: rate={args.rate} eps, duration={args.duration}s")

    poll_session = requests.Session()
    login(poll_session, args.base_url, args.username, args.password)

    poller = Poller(args.base_url, poll_session, run_id)
    poller.start()

    total_sent, accepted = send_events(args.base_url, args.ingest_token, run_id, args.rate, args.duration, poller)

    print("Waiting for any remaining events to become visible...")
    latencies, missing = poller.wait_for_all(timeout=args.poll_timeout)
    poller.stop()

    report(latencies, missing, total_sent, accepted)


if __name__ == "__main__":
    main()
