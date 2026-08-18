"""UDP + TCP syslog listeners. Each accepted line/datagram is tagged with the sender's
IP as a host_hint and pushed onto the RawQueue without any parsing or blocking work (§3, §3.1).
"""
import logging
import socket
import threading
from datetime import datetime, timezone

logger = logging.getLogger("sentrylite.syslog")

_RECV_BUFSIZE = 65535


def udp_listener(raw_queue, bind, port, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.settimeout(1.0)
    logger.info("syslog UDP listener bound to %s:%s", bind, port)

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(_RECV_BUFSIZE)
        except socket.timeout:
            continue
        except OSError:
            if stop_event.is_set():
                break
            logger.exception("UDP recv error")
            continue

        message = data.decode("utf-8", errors="replace").strip()
        if message:
            raw_queue.put(None, message, received_at=datetime.now(timezone.utc), host_hint=addr[0])

    sock.close()


def _handle_tcp_connection(conn, addr, raw_queue, stop_event):
    conn.settimeout(1.0)
    buf = b""
    try:
        while not stop_event.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                message = line.decode("utf-8", errors="replace").strip()
                if message:
                    raw_queue.put(None, message, received_at=datetime.now(timezone.utc), host_hint=addr[0])
    except OSError:
        pass
    finally:
        conn.close()


def tcp_listener(raw_queue, bind, port, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(50)
    sock.settimeout(1.0)
    logger.info("syslog TCP listener bound to %s:%s", bind, port)

    conn_threads = []
    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop_event.is_set():
                break
            logger.exception("TCP accept error")
            continue

        t = threading.Thread(
            target=_handle_tcp_connection, args=(conn, addr, raw_queue, stop_event), daemon=True
        )
        t.start()
        conn_threads.append(t)

    sock.close()
