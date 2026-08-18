#!/usr/bin/env python
"""Synthetic benign + attack traffic generator for SentryLite (README section 13).

Sends raw log lines over UDP syslog to --target (host:port) at the requested rate,
and writes a ground-truth CSV alongside the run (one row per line sent, flagged
attack/benign) so the triage engine's precision/recall can be computed afterwards
by cross-referencing against what actually landed in the `event` table.

Usage:
    python tools/log_generator.py --mode mixed --rate 20 --duration 120 --target localhost:5514
    python tools/log_generator.py --mode brute-force --rate 50 --duration 10 --target localhost:5514
"""
import argparse
import csv
import ipaddress
import random
import socket
import time
import uuid
from datetime import datetime, timezone

MODES = ("benign", "brute-force", "port-scan", "traversal", "sqli", "mixed")

_USERS = ["alice", "bob", "carol", "dave", "svc-app"]
_ADMIN_USERS = ["root", "admin", "administrator"]
_PATHS = ["/", "/index.html", "/products", "/login", "/api/v1/status", "/dashboard"]
_TRAVERSAL_PAYLOADS = [
    "/../../etc/passwd",
    "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "/static/..\\..\\..\\windows\\win.ini",
]
# Access-log request paths can't contain a raw space (a real HTTP client would
# percent-encode it); spaces here are %20-encoded so the generated line matches the
# combined log format our own parser (and any real one) expects.
_SQLI_PAYLOADS = [
    "/product?id=1'%20OR%20'1'='1",
    "/search?q=union+select+username,password+from+users",
    "/login?user=admin'--&pass=x",
    "/item?id=1;SELECT%20SLEEP(5)",
]


def _rand_ip(private=False):
    if private:
        return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return str(ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF)))


def _now_syslog_ts(dt):
    """RFC 3164 timestamp: 'Mmm dd hh:mm:ss', day space-padded (not zero-padded)."""
    day = dt.strftime("%d")
    if day.startswith("0"):
        day = " " + day[1:]
    return f"{dt.strftime('%b')} {day} {dt.strftime('%H:%M:%S')}"


def _auth_line(dt, host, tag, pid, msg):
    return f"{_now_syslog_ts(dt)} {host} {tag}[{pid}]: {msg}"


def _access_line(dt, ip, method, path, status, agent="Mozilla/5.0"):
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {random.randint(100, 5000)} "-" "{agent}"'


def gen_benign(n, start_dt):
    out = []
    for i in range(n):
        dt = start_dt
        if random.random() < 0.5:
            ip = _rand_ip(private=random.random() < 0.4)
            user = random.choice(_USERS)
            line = _auth_line(dt, "web01", "sshd", 1000 + i, f"Accepted password for {user} from {ip} port {40000+i} ssh2")
        else:
            ip = _rand_ip()
            line = _access_line(dt, ip, "GET", random.choice(_PATHS), 200)
        out.append((line, False, "benign"))
    return out


def gen_brute_force(n, start_dt):
    out = []
    attacker_ip = _rand_ip()
    target_user = random.choice(_USERS + _ADMIN_USERS)
    fail_count = max(6, n - 1)
    for i in range(fail_count):
        line = _auth_line(
            start_dt, "web01", "sshd", 2000 + i,
            f"Failed password for invalid user {target_user} from {attacker_ip} port {50000+i} ssh2",
        )
        out.append((line, True, "brute-force"))
    line = _auth_line(
        start_dt, "web01", "sshd", 2000 + fail_count,
        f"Accepted password for {target_user} from {attacker_ip} port {50000+fail_count} ssh2",
    )
    out.append((line, True, "brute-force"))
    return out[:n] if n < len(out) else out


def gen_port_scan(n, start_dt):
    out = []
    attacker_ip = _rand_ip()
    ports = random.sample(range(1, 65535), max(16, n))
    for port in ports[:n]:
        payload = (
            '{"event_type": "NETWORK_CONNECTION", "src_ip": "%s", "dest_ip": "10.0.0.5", '
            '"dest_port": %d, "protocol": "TCP", "message": "connection attempt", '
            '"timestamp": "%s"}'
        ) % (attacker_ip, port, start_dt.isoformat())
        out.append((payload, True, "port-scan"))
    return out


def gen_traversal(n, start_dt):
    out = []
    ip = _rand_ip()
    for i in range(n):
        path = random.choice(_TRAVERSAL_PAYLOADS)
        line = _access_line(start_dt, ip, "GET", path, 403)
        out.append((line, True, "traversal"))
    return out


def gen_sqli(n, start_dt):
    out = []
    ip = _rand_ip()
    for i in range(n):
        path = random.choice(_SQLI_PAYLOADS)
        line = _access_line(start_dt, ip, "GET", path, 500)
        out.append((line, True, "sqli"))
    return out


_GENERATORS = {
    "benign": gen_benign,
    "brute-force": gen_brute_force,
    "port-scan": gen_port_scan,
    "traversal": gen_traversal,
    "sqli": gen_sqli,
}


def build_batch(mode, count, start_dt):
    if mode != "mixed":
        return _GENERATORS[mode](count, start_dt)

    batch = []
    remaining = count
    weights = {"benign": 0.55, "brute-force": 0.15, "port-scan": 0.1, "traversal": 0.1, "sqli": 0.1}
    for sub_mode, weight in weights.items():
        sub_count = max(1, int(count * weight))
        sub_count = min(sub_count, remaining)
        if sub_count <= 0:
            continue
        batch.extend(_GENERATORS[sub_mode](sub_count, start_dt))
        remaining -= sub_count
    if remaining > 0:
        batch.extend(gen_benign(remaining, start_dt))
    random.shuffle(batch)
    return batch[:count]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=MODES, default="mixed")
    parser.add_argument("--rate", type=float, default=10.0, help="events per second")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    parser.add_argument("--target", default="localhost:5514", help="host:port of the syslog UDP listener")
    parser.add_argument("--out", default=None, help="ground-truth CSV path (default: <mode>_ground_truth.csv)")
    args = parser.parse_args()

    host, port_str = args.target.rsplit(":", 1)
    port = int(port_str)
    out_path = args.out or f"{args.mode.replace('-', '_')}_ground_truth.csv"

    total = max(1, int(args.rate * args.duration))
    batch = build_batch(args.mode, total, datetime.now(timezone.utc))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / args.rate if args.rate > 0 else 0

    print(f"Sending {len(batch)} line(s) to {host}:{port} at ~{args.rate} eps over ~{args.duration}s (mode={args.mode})")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["index", "run_id", "sent_at", "attack_type", "is_attack", "raw_message"])
        run_id = uuid.uuid4().hex[:8]
        start = time.monotonic()
        for i, (line, is_attack, attack_type) in enumerate(batch):
            sock.sendto(line.encode("utf-8"), (host, port))
            writer.writerow([i, run_id, datetime.now(timezone.utc).isoformat(), attack_type, is_attack, line])
            if interval:
                time.sleep(interval)

        elapsed = time.monotonic() - start

    sock.close()
    print(f"Done in {elapsed:.1f}s. Ground truth written to {out_path}")
    print(f"Attack lines: {sum(1 for _, a, _ in batch if a)} / {len(batch)}")


if __name__ == "__main__":
    main()
