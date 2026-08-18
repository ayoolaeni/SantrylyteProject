"""Wires up the RawQueue, syslog listeners, worker pool and correlator sweeper.

Called once from run.py after create_app() — never from create_app() itself, so
importing the app (as pytest does) never opens sockets or spawns background threads.
"""
import logging
import threading
import time
from datetime import datetime, timezone

from app.ingestion.syslog_server import tcp_listener, udp_listener
from app.ingestion.worker import worker_loop
from app.triage.correlator import correlator

logger = logging.getLogger("sentrylite.bootstrap")


def _sweeper_loop(stop_event, interval=60):
    while not stop_event.is_set():
        stop_event.wait(interval)
        try:
            correlator.sweep(datetime.now(timezone.utc))
        except Exception:
            logger.exception("correlator sweep failed")


def start_services(app):
    stop_event = threading.Event()
    raw_queue = app.raw_queue
    app.ingestion_stop_event = stop_event
    threads = []

    if app.config.get("SYSLOG_ENABLED", True):
        udp_t = threading.Thread(
            target=udp_listener,
            args=(raw_queue, app.config["SYSLOG_BIND"], app.config["SYSLOG_UDP_PORT"], stop_event),
            daemon=True,
            name="syslog-udp",
        )
        tcp_t = threading.Thread(
            target=tcp_listener,
            args=(raw_queue, app.config["SYSLOG_BIND"], app.config["SYSLOG_TCP_PORT"], stop_event),
            daemon=True,
            name="syslog-tcp",
        )
        udp_t.start()
        tcp_t.start()
        threads += [udp_t, tcp_t]

    for i in range(app.config["TRIAGE_WORKERS"]):
        t = threading.Thread(
            target=worker_loop, args=(app, raw_queue, stop_event, i), daemon=True, name=f"triage-worker-{i}"
        )
        t.start()
        threads.append(t)

    sweeper_t = threading.Thread(target=_sweeper_loop, args=(stop_event,), daemon=True, name="correlator-sweeper")
    sweeper_t.start()
    threads.append(sweeper_t)

    app.ingestion_threads = threads
    logger.info("ingestion services started: %d thread(s)", len(threads))
    return stop_event
