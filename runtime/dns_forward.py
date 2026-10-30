#!/usr/bin/env python3
"""Minimal, auditable DNS split forwarder for the isolated runtime.

Why this exists: the enterprise split path must be something this project can
reason about. dnsmasq accepted every configuration we generated and forwarded the
corporate query (proven by `--log-queries` and by the relay's own log), but its
upstream socket never received the replies inside this container, while an
identically bound socket built here always did. Rather than keep a resolver we
cannot observe, the split path is served by this forwarder.

Contract:
  * It reads the SAME `dnsmasq.servers` policy file the DNS owner already renders,
    so ownership, atomic replacement and HUP semantics are unchanged.
  * `server=/corp.test/10.91.0.53@labtun0` means: for `corp.test` and everything
    below it, ask 10.91.0.53 with the socket bound to `labtun0`.
  * `server=/corp.test/` (no upstream) means the domain is deliberately BLOCKED:
    answer NXDOMAIN and never fall back to a public resolver.
  * A bare `server=127.0.0.11` is a bootstrap upstream for everything else.
  * Unmatched names with no bootstrap upstream get SERVFAIL, never a guess.

The process only ever binds loopback and only ever sends to resolvers named in the
policy file; it never writes configuration and never touches firewall state.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import threading
import time

MAX_MESSAGE = 1232
DEFAULT_TIMEOUT = 3.0
# One stalled corporate resolver must not queue every other lookup behind it.
MAX_WORKERS = 16
MAX_INFLIGHT = 256
# DNS over TCP (RFC 1035 §4.2.2) can carry far more than a UDP datagram.
MAX_TCP_MESSAGE = 65535
TCP_TIMEOUT = 5.0
MAX_DEPTH = 16


class PolicyError(ValueError):
    """The policy file is unreadable or malformed; fail closed."""


def _parse_server(line: str):
    """Return ('default', ip, iface) or ('domain', suffix, ip|None, iface)."""
    body = line.strip()[len("server="):]
    iface = ""
    if "@" in body:
        body, iface = body.split("@", 1)
        if not iface or not all(ch.isalnum() or ch in "_.-" for ch in iface):
            raise PolicyError("invalid interface in server line")
    if body.startswith("/"):
        parts = body.split("/")
        # server=/domain/address  -> ['', 'domain', 'address']
        if len(parts) != 3:
            raise PolicyError("invalid domain server line")
        suffix = parts[1].strip(".").lower()
        address = parts[2].strip()
        if not suffix or any(ch in suffix for ch in "/@"):
            raise PolicyError("invalid domain suffix")
        if not address:
            return ("domain", suffix, None, "")
        return ("domain", suffix, address, iface)
    address = body.strip()
    if not address:
        raise PolicyError("empty default server")
    return ("default", address, iface)


def load_policy(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PolicyError(f"cannot open policy: {exc}") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise PolicyError("policy must be a regular file")
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise PolicyError("policy file too large")
    defaults, domains = [], {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("server="):
            raise PolicyError("unsupported directive")
        parsed = _parse_server(line)
        if parsed[0] == "default":
            defaults.append((parsed[1], parsed[2]))
        else:
            domains[parsed[1]] = (parsed[2], parsed[3])
    return {"defaults": defaults[:8], "domains": domains}


def _qname(query: bytes):
    """Parse the question section; return (labels, end_offset) or raise."""
    if len(query) < 12:
        raise PolicyError("short query")
    offset, labels, total = 12, [], 0
    while True:
        if offset >= len(query):
            raise PolicyError("truncated name")
        length = query[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(query):
            raise PolicyError("invalid label")
        total += length + 1
        if total > 253 or len(labels) >= MAX_DEPTH:
            raise PolicyError("name too long")
        labels.append(query[offset:offset + length].decode("ascii", "replace").lower())
        offset += length
    if offset + 4 > len(query):
        raise PolicyError("truncated question")
    return ".".join(labels), offset + 4


def _servfail(query: bytes) -> bytes:
    """Build a SERVFAIL without depending on the query being well formed.

    This used to re-parse the query to copy the question section, so a malformed
    datagram made the error path raise again — killing the forwarder and with it
    every lookup in the container.
    """
    if len(query) < 2:
        return b""  # cannot echo a transaction id: drop instead of answering
    flags = 0x8182  # response, recursion desired available, SERVFAIL
    try:
        question = query[12:_qname(query)[1]]
    except PolicyError:
        question = b""
    header = struct.pack("!HHHHH", flags, 1 if question else 0, 0, 0, 0)
    return query[:2] + header + question


def _nxdomain(query: bytes) -> bytes:
    flags = 0x8183  # response, NXDOMAIN
    return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:_qname(query)[1]]


def select_upstream(policy: dict, name: str):
    """Longest-suffix match; returns (address, iface, blocked)."""
    best = None
    for suffix, (address, iface) in policy["domains"].items():
        if name == suffix or name.endswith("." + suffix):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, address, iface)
    if best is not None:
        return best[1], best[2], best[1] is None
    if policy["defaults"]:
        address, iface = policy["defaults"][0]
        return address, iface, False
    return None, "", True


def forward(query: bytes, address: str, iface: str, timeout: float = DEFAULT_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        if iface:
            # Same binding the manual probe proves works in this container.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\x00")
        sock.sendto(query, (address, 53))
        while True:
            reply, _ = sock.recvfrom(MAX_MESSAGE)
            if reply[:2] == query[:2]:
                return reply
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def _answer(query: bytes, policy: dict) -> bytes:
    """Resolve one query against an immutable policy snapshot."""
    try:
        name, _ = _qname(query)
    except PolicyError:
        return _servfail(query)
    address, iface, blocked = select_upstream(policy, name)
    if blocked:
        return _nxdomain(query) or _servfail(query)
    reply = forward(query, address, iface) if address else None
    return reply or _servfail(query)


def _recv_exact(sock, count: int):
    """Read exactly `count` bytes, or return None on a short/closed stream."""
    chunks, got = [], 0
    while got < count:
        chunk = sock.recv(count - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _tcp_connection(conn, policy: dict) -> None:
    """Serve one DNS-over-TCP exchange: 2-byte length prefix, then the message."""
    try:
        conn.settimeout(TCP_TIMEOUT)
        header = _recv_exact(conn, 2)
        if header is None:
            return
        (length,) = struct.unpack("!H", header)
        if length < 12 or length > MAX_TCP_MESSAGE:
            return
        query = _recv_exact(conn, length)
        if query is None or len(query) != length:
            return
        reply = _answer(query, policy)
        if reply:
            conn.sendall(struct.pack("!H", len(reply)) + reply)
    except (OSError, struct.error):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _tcp_accept_loop(tcp_sock, policy_box, pool, stopping) -> None:
    tcp_sock.settimeout(0.5)
    while not stopping["flag"]:
        try:
            conn, _ = tcp_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            pool.submit(_tcp_connection, conn, policy_box["policy"])
        except RuntimeError:
            conn.close()


def serve(policy_path: Path, listen: str = "127.0.0.1", port: int = 53, stop_after=None,
          wait_for_policy: float = 60.0, workers: int = MAX_WORKERS):
    # The DNS owner renders the policy on its own schedule; starting before that
    # must not be fatal, otherwise readiness never settles into DNS-activate.
    deadline = time.time() + wait_for_policy
    while True:
        try:
            policy = load_policy(policy_path)
            break
        except PolicyError:
            if time.time() >= deadline:
                raise
            time.sleep(0.25)
    stamp = policy_path.stat().st_mtime
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen, port))
    server.settimeout(0.5)
    # RFC 1035 requires TCP for truncated/large answers. A bind failure here is
    # reported but must not take UDP down with it.
    tcp_server = None
    try:
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind((listen, port))
        tcp_server.listen(16)
    except OSError as exc:
        print("dns forward: tcp listener unavailable (%s); udp only" % type(exc).__name__,
              file=sys.stderr)
        if tcp_server is not None:
            tcp_server.close()
        tcp_server = None
    stopping = {"flag": False}
    reloading = {"flag": False}
    inflight = {"count": 0}
    guard = threading.Lock()

    def _stop(*_):
        stopping["flag"] = True

    def _reload(*_):
        # SIGHUP means "re-read the policy", never "exit": the DNS owner uses it
        # as its reload primitive, so treating it as termination caused a restart
        # loop and readiness could never settle.
        reloading["flag"] = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)
    signal.signal(signal.SIGHUP, _reload)

    def _work(query, peer, snapshot):
        """Runs in the pool: never let one exception kill the forwarder."""
        try:
            reply = _answer(query, snapshot)
        except Exception:  # defensive: a resolver bug must not take DNS down
            reply = _servfail(query)
        try:
            if reply:
                server.sendto(reply, peer)
        except OSError:
            pass
        finally:
            with guard:
                inflight["count"] -= 1

    # A single-threaded pool keeps the old serial behaviour available for tests
    # and for debugging a suspected ordering problem.
    pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="dnsfwd")
    policy_box = {"policy": policy}
    tcp_thread = None
    if tcp_server is not None:
        tcp_thread = threading.Thread(target=_tcp_accept_loop, daemon=True,
                                      args=(tcp_server, policy_box, pool, stopping))
        tcp_thread.start()
    hard_deadline = time.time() + stop_after if stop_after else None
    try:
        while not stopping["flag"]:
            if hard_deadline and time.time() >= hard_deadline:
                break
            try:
                query, peer = server.recvfrom(MAX_MESSAGE)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if reloading["flag"] or policy_path.stat().st_mtime != stamp:
                    reloading["flag"] = False
                    policy = load_policy(policy_path)  # new dict: older tasks keep theirs
                    policy_box["policy"] = policy
                    stamp = policy_path.stat().st_mtime
            except OSError:
                pass
            except PolicyError:
                # Keep serving with the last known good policy rather than dying on
                # a half-written or invalid file.
                pass
            with guard:
                overloaded = inflight["count"] >= MAX_INFLIGHT
                if not overloaded:
                    inflight["count"] += 1
            if overloaded:
                busy = _servfail(query)
                if busy:
                    try:
                        server.sendto(busy, peer)
                    except OSError:
                        pass
                continue
            pool.submit(_work, query, peer, policy)
    finally:
        stopping["flag"] = True
        pool.shutdown(wait=False, cancel_futures=True)
        server.close()
        if tcp_server is not None:
            tcp_server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--pid-file", type=Path)
    args = parser.parse_args(argv)
    if args.pid_file is not None:
        if args.pid_file.is_symlink():
            print("dns forward: refusing symlinked pid file", file=sys.stderr)
            return 2
        args.pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(args.pid_file, 0o600)
    try:
        serve(args.policy, args.listen, args.port)
    except PolicyError as exc:
        print(f"dns forward: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"dns forward: bind failed ({exc.__class__.__name__})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
