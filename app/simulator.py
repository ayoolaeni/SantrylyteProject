"""Built-in attack simulator: realistic log lines pushed through the real ingestion pipeline.

Lines go onto the same RawQueue the syslog listener and ingest API feed, attributed to an
"Attack Simulator" log source, so parsing, rule matching, critical-asset scoring, incident
creation and the live dashboard all behave exactly as they would for real traffic.
"""
import ipaddress
import json
import logging
import random
import time
from datetime import datetime, timezone

logger = logging.getLogger("sentrylite.simulator")

SIMULATOR_SOURCE_NAME = "Attack Simulator"
WEB_SERVER_IP = "10.0.0.20"        # inside the seeded "Core server subnet" critical asset
DOMAIN_CONTROLLER_IP = "10.0.0.10"  # the seeded "Primary domain controller" critical asset

_USERS = ["alice", "bob", "carol", "dave", "svc-backup"]
_PAGES = ["/", "/index.html", "/products", "/cart", "/api/v1/status", "/about", "/contact"]
_SQLI = [
    "/product?id=1' OR '1'='1",
    "/search?q=1 UNION SELECT username,password FROM users",
    "/login?user=admin' OR '1'='1'--&pass=x",
    "/item?id=1;SELECT SLEEP(5)",
]
_TRAVERSAL = [
    "/download?file=../../../../etc/passwd",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
    "/images/../../../windows/win.ini",
]


def _now():
    return datetime.now(timezone.utc)


def _syslog_ts(dt):
    return f"{dt.strftime('%b')} {dt.day:>2} {dt.strftime('%H:%M:%S')}"


def _web_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000))
        if ip.is_global:
            return str(ip)


def _auth(host, tag, msg):
    return lambda: f"{_syslog_ts(_now())} {host} {tag}[{random.randint(1000, 9999)}]: {msg}"


def _json(**fields):
    def build():
        return json.dumps({"timestamp": _now().isoformat(), **fields})
    return build


def _access(ip, method, path, status, agent="Mozilla/5.0"):
    path = path.replace(" ", "%20")
    return lambda: f'{ip} - - [{_web_ts(_now())}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{agent}"'


# Each step is (delay_before_seconds, line_builder). Builders run at send time so every
# line carries the moment it was "logged", like real traffic.

def _brute_force(ip):
    user = random.choice(["root", "admin"])
    steps = [(0.25, _auth("web01", "sshd", f"Failed password for {user} from {ip} port {50000 + i} ssh2")) for i in range(10)]
    steps.append((1.0, _auth("web01", "sshd", f"Accepted password for {user} from {ip} port 50999 ssh2")))
    return steps


def _port_scan(ip, target=DOMAIN_CONTROLLER_IP):
    ports = random.sample([21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306,
                           3389, 5432, 5900, 5985, 8080, 8443, 9200], 22)
    return [
        (0.12, _json(event_type="NETWORK_CONNECTION", src_ip=ip, dest_ip=target, dest_port=p, protocol="TCP",
                     action="DENY", hostname="fw01", message=f"Inbound connection attempt to {target}:{p}"))
        for p in ports
    ]


def _sqli(ip):
    return [
        (0.6, _json(event_type="WEB_REQUEST", src_ip=ip, dest_ip=WEB_SERVER_IP, hostname="shop01", http_method="GET",
                    http_path=random.choice(_SQLI), http_status=500, user_agent="sqlmap/1.7",
                    message="Web request with SQL injection payload"))
        for _ in range(6)
    ]


def _traversal(ip):
    return [
        (0.6, _json(event_type="WEB_REQUEST", src_ip=ip, dest_ip=WEB_SERVER_IP, hostname="shop01", http_method="GET",
                    http_path=random.choice(_TRAVERSAL), http_status=403, user_agent="Nikto/2.5",
                    message="Web request trying to escape the web root"))
        for _ in range(5)
    ]


def _web_login_brute_force(ip):
    return [(0.1, _access(ip, "POST", "/wp-login.php", 401, agent="python-requests/2.31")) for _ in range(25)]


def _privilege_escalation(_ip):
    return [
        (0.5, _auth("db01", "useradd", "new user: name=backdoor, UID=1050, GID=1050, home=/home/backdoor, shell=/bin/bash")),
        (1.0, _auth("db01", "usermod", "add 'backdoor' to group 'sudo'")),
        (1.0, _auth("db01", "sudo", "backdoor : TTY=pts/1 ; PWD=/home/backdoor ; USER=root ; COMMAND=/bin/bash")),
    ]


def _data_theft(ip):
    return [
        (0.8, _json(event_type="FILE_ACCESS", src_ip=ip, dest_ip=WEB_SERVER_IP, hostname="shop01", username="www-data",
                    message=f"Read access to {path} by www-data"))
        for path in ("/etc/passwd", "/etc/shadow", "/var/www/.env", "/home/admin/.ssh/id_rsa")
    ]


def _log_tampering(ip):
    return [
        (1.0, _json(event_type="SERVICE_STOP", src_ip=ip, dest_ip=DOMAIN_CONTROLLER_IP, hostname="dc01", username="backdoor",
                    message="Stopped rsyslog system logging service")),
    ]


def _benign(_ip, count=30):
    steps = []
    for _ in range(count):
        if random.random() < 0.5:
            user = random.choice(_USERS)
            src = f"10.0.{random.randint(1, 9)}.{random.randint(2, 250)}"
            steps.append((0.15, _auth("web01", "sshd", f"Accepted publickey for {user} from {src} port {random.randint(40000, 60000)} ssh2")))
        else:
            steps.append((0.15, _access(_public_ip(), "GET", random.choice(_PAGES), random.choice([200, 200, 200, 304]))))
    return steps


def _kill_chain(ip):
    pause = lambda steps, seconds: [(seconds, steps[0][1])] + steps[1:]  # noqa: E731
    return (
        _port_scan(ip, target=WEB_SERVER_IP)
        + pause(_brute_force(ip), 3.0)
        + pause(_privilege_escalation(ip), 3.0)
        + pause(_data_theft(ip), 3.0)
        + pause(_log_tampering(ip), 3.0)
    )


SCENARIOS = {
    "brute_force": {
        "name": "SSH brute force & break-in",
        "mitre": "T1110 Brute Force",
        "description": "An attacker guesses the root/admin SSH password 10 times, then gets in.",
        "expect": "MEDIUM/HIGH 'Repeated failed login' alerts, then a CRITICAL incident when the login succeeds.",
        "build": _brute_force,
    },
    "port_scan": {
        "name": "Port scan on the domain controller",
        "mitre": "T1046 Network Service Discovery",
        "description": "22 connection attempts to different ports on 10.0.0.10, a critical asset.",
        "expect": "'Port scan pattern' fires and the critical-asset multiplier (x2) pushes it to HIGH or CRITICAL.",
        "build": _port_scan,
    },
    "sqli": {
        "name": "SQL injection on the web shop",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "sqlmap-style requests with SQL injection payloads against the shop server.",
        "expect": "HIGH 'SQL injection attempt' alerts (score boosted because the target is in the core server subnet).",
        "build": _sqli,
    },
    "traversal": {
        "name": "Directory traversal",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "Requests trying to read files outside the web root (../../etc/passwd).",
        "expect": "HIGH 'Directory traversal' alerts against the shop server.",
        "build": _traversal,
    },
    "web_login": {
        "name": "Website login brute force",
        "mitre": "T1110 Brute Force",
        "description": "25 failed WordPress logins (HTTP 401) from one IP in a few seconds.",
        "expect": "'Web brute force' fires once the 20-failure threshold is passed.",
        "build": _web_login_brute_force,
    },
    "privilege_escalation": {
        "name": "Backdoor account & privilege escalation",
        "mitre": "T1136 Create Account / T1548 Abuse Elevation",
        "description": "A new 'backdoor' user is created, added to sudo, then becomes root.",
        "expect": "'Account created' and 'Privilege escalation' alerts on db01.",
        "build": _privilege_escalation,
    },
    "data_theft": {
        "name": "Sensitive file access",
        "mitre": "T1005 Data from Local System",
        "description": "The web server account reads /etc/shadow, SSH keys and the app's .env secrets.",
        "expect": "HIGH 'Sensitive file access' alerts on the shop server.",
        "build": _data_theft,
    },
    "log_tampering": {
        "name": "Attacker stops logging",
        "mitre": "T1562 Impair Defenses",
        "description": "The logging service on the domain controller is stopped to hide activity.",
        "expect": "A CRITICAL alert and incident ('Log service stopped' on a x2 critical asset).",
        "build": _log_tampering,
    },
    "kill_chain": {
        "name": "Full attack chain",
        "mitre": "Recon -> Access -> Escalation -> Theft -> Cover tracks",
        "description": "One attacker runs the whole story over ~25 seconds: scan, break in, escalate, steal, hide.",
        "expect": "The dashboard fills up stage by stage, ending with CRITICAL incidents. Best scenario for a live demo.",
        "build": _kill_chain,
    },
    "benign": {
        "name": "Normal business traffic",
        "mitre": "-",
        "description": "30 everyday logins and page views, so you can see how normal activity scores.",
        "expect": "INFORMATIONAL events only. No alerts, no incidents.",
        "build": _benign,
    },
}


def scenario_list():
    return [
        {"id": key, "name": s["name"], "mitre": s["mitre"], "description": s["description"], "expect": s["expect"]}
        for key, s in SCENARIOS.items()
    ]


def get_or_create_simulator_source():
    from app.extensions import db
    from app.models.log_source import LogSource

    source = LogSource.query.filter_by(name=SIMULATOR_SOURCE_NAME).first()
    if source is None:
        source = LogSource(name=SIMULATOR_SOURCE_NAME, host_identifier="simulator", source_type="SYSLOG", is_enabled=True)
        db.session.add(source)
        db.session.commit()
    elif not source.is_enabled:
        source.is_enabled = True
        db.session.commit()
    return source.source_id


def build_steps(scenario):
    spec = SCENARIOS[scenario]
    attacker_ip = _public_ip()
    return attacker_ip, spec["build"](attacker_ip)


def _deliver(app, source_id, steps):
    """Push each line onto the queue after its delay, so the dashboard animates like real traffic."""
    from app.extensions import socketio

    for delay, builder in steps:
        if delay:
            socketio.sleep(delay)
        try:
            app.raw_queue.put(source_id, builder(), received_at=_now())
        except Exception:
            logger.exception("simulator failed to enqueue a line")


def run_scenario(app, scenario):
    """Start a scenario. Returns (attacker_ip, line_count, approx_seconds)."""
    source_id = get_or_create_simulator_source()
    attacker_ip, steps = build_steps(scenario)
    seconds = round(sum(d for d, _ in steps), 1)

    if app.config.get("TESTING"):
        from app.ingestion.worker import process_pending

        for _, builder in steps:
            app.raw_queue.put(source_id, builder(), received_at=_now())
        process_pending(app, app.raw_queue, max_items=len(steps) + 5)
    else:
        from app.extensions import socketio

        socketio.start_background_task(_deliver, app, source_id, steps)
    return attacker_ip, len(steps), seconds


# ---------- continuous background traffic ----------

_background = {"running": False, "until": None, "started_by": None, "generation": 0}


def background_status():
    running = _background["running"] and _background["until"] and time.time() < _background["until"]
    return {
        "running": bool(running),
        "seconds_left": max(0, int(_background["until"] - time.time())) if running else 0,
        "started_by": _background["started_by"] if running else None,
    }


def start_background(app, minutes, started_by):
    _background.update(running=True, until=time.time() + minutes * 60, started_by=started_by)
    _background["generation"] += 1
    if app.config.get("TESTING"):
        return
    from app.extensions import socketio

    with app.app_context():
        source_id = get_or_create_simulator_source()
    socketio.start_background_task(_background_loop, app, source_id, _background["generation"])


def stop_background():
    _background.update(running=False, until=None, started_by=None)
    _background["generation"] += 1


def _background_loop(app, source_id, generation):
    """Steady everyday traffic with an occasional small attack, until stopped or timed out."""
    from app.extensions import socketio

    next_attack = time.time() + random.uniform(20, 40)
    while _background["generation"] == generation and background_status()["running"]:
        for _, builder in _benign(None, count=random.randint(1, 3)):
            app.raw_queue.put(source_id, builder(), received_at=_now())
        if time.time() >= next_attack:
            attack = random.choice(["sqli", "traversal", "data_theft", "brute_force"])
            _, steps = build_steps(attack)
            socketio.start_background_task(_deliver, app, source_id, steps[:6])
            next_attack = time.time() + random.uniform(30, 60)
        socketio.sleep(random.uniform(0.8, 1.6))
    if _background["generation"] == generation:
        _background.update(running=False, until=None, started_by=None)
