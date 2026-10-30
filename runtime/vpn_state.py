#!/usr/bin/env python3
"""Bounded, fail-closed VPN readiness; no third-party Python dependencies.

CLI: run | once | status | check | drain [--state-dir /run/feilian].
status/check are read-only, including on missing/malformed state. check exits 0
for the selected ready/live predicate, 1 otherwise (Docker health may adapt it).
run/once write schema-v1 status.json atomically, mode 0600; heartbeat TTL is 20s.
A failed probe removes readiness on that sample; two consecutive successes are
required. Waiting for authentication is live and never asks for a client restart.

Readiness requires routed, active VPN interface(s), non-stale VPN DNS, a direct
enterprise DNS query, and verified internal HTTPS with exact expected status.
Targets must match corporate suffixes (if supplied) and corporate CIDRs (if
supplied); without CIDRs only RFC1918/CGN IPv4 targets qualify. Public HTTP 200,
login redirects, a tun-looking name, vpn.conf existence or process presence are
not sufficient. IPv6-only probe targets deliberately cannot establish readiness
for the first, IPv4-only data plane.

The resolver contacts ONLY validated VPN DNS, not getaddrinfo/public fallback.
HTTPS is pinned to the validated target/source addresses while preserving TLS
hostname verification; urllib environment proxies and redirects are disabled.
No credentials, full VPN JSON, URL, response body or exception text enter status.
VPN_CONFIG_FILE snapshots are capped at 64KiB; snapshots older than 300s are
marked stale candidates, NEVER independent evidence of a current session. They
can qualify only after every fresh interface/route/DNS/HTTPS probe succeeds.
Thus a long-lived session need not rewrite an otherwise unchanged vpn.conf.

DNSManager generates configuration but NEVER starts dnsmasq or network guards.
The supervisor must launch dnsmasq and coordinate proxy/guard teardown BEFORE
terminating this controller. drain withdraws ready immediately without stopping
the client. SIGTERM publishes DRAINING then restores only still-owned DNS.
Tests inject Runner, Clock, Resolver, HTTPS probe and DNSManager; never use live
network, real VPN files or host resolver mutations in a unit test.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from .dns_manager import (DNSManager, DNSError, atomic_write, dns_addresses,
                              domain_name, read_regular, secure_directory)
except ImportError:  # executable script, not an installed package
    from dns_manager import (DNSManager, DNSError, atomic_write, dns_addresses,
                             domain_name, read_regular, secure_directory)

TTL = 20
CONFIG_MAX_AGE = 300
PROBE_BUDGET = 10
STATES = frozenset(("UNCONFIGURED", "WAITING_AUTH", "VALIDATING", "READY",
                    "DEGRADED", "DISCONNECTED", "DRAINING"))
CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
EVIDENCE_KEYS = frozenset(("interface", "interface_ifindex", "vpn_ipv4", "dns_servers", "dns_source",
                           "dns_age_seconds", "dns_config_stale", "target_count", "https_status",
                           "success_count", "success_required", "dns_managed",
                           "dns_active", "dns_mode", "config_id"))
INTERNAL_V4 = tuple(ipaddress.ip_network(value) for value in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


class ConfigError(Exception):
    pass


class ProbeError(Exception):
    pass


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def bounded_json(raw, limit=65536):
    if len(raw) > limit:
        raise ValueError("size limit")
    value = json.loads(raw, object_pairs_hook=_no_duplicates,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
    count = 0

    def validate(node, depth=0):
        nonlocal count
        count += 1
        if depth > 8 or count > 1024:
            raise ValueError("structure limit")
        if isinstance(node, dict):
            if len(node) > 64 or any(len(key) > 128 for key in node):
                raise ValueError("field limit")
            for item in node.values():
                validate(item, depth + 1)
        elif isinstance(node, list):
            if len(node) > 128:
                raise ValueError("array limit")
            for item in node:
                validate(item, depth + 1)
        elif isinstance(node, str) and len(node) > 4096:
            raise ValueError("string limit")
    validate(value)
    return value


def _absolute_path(value, code):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ConfigError(code)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(code)
    return path


def _split(value, limit, code):
    if not isinstance(value, str) or len(value) > 16384:
        raise ConfigError(code)
    if not value.strip():
        return ()
    parts = tuple(part.strip() for part in value.split(","))
    if len(parts) > limit or any(not part for part in parts):
        raise ConfigError(code)
    return tuple(dict.fromkeys(parts))


def in_suffix(name, domains):
    return any(name == suffix or name.endswith("." + suffix) for suffix in domains)


def valid_evidence(evidence):
    if not isinstance(evidence, dict) or not set(evidence) <= EVIDENCE_KEYS:
        return False
    for key, value in evidence.items():
        if key in ("dns_managed", "dns_active", "dns_config_stale"):
            if type(value) is not bool:
                return False
        elif key in ("success_count", "success_required", "target_count", "https_status", "dns_age_seconds"):
            if type(value) is not int or value < 0 or value > 2**53:
                return False
            if key == "success_count" and value > 10 or key == "success_required" and not 1 <= value <= 10:
                return False
            if key == "target_count" and value > 16 or key == "https_status" and not 200 <= value <= 299:
                return False
        elif key == "interface":
            if not isinstance(value, str) or not IFACE.fullmatch(value) or value == "lo":
                return False
        elif key == "interface_ifindex":
            # Kernel interface index pins the DNS upstream binding across a
            # same-name tunnel rebuild; None is allowed only when unobserved.
            if value is not None and (type(value) is not int or not 1 <= value <= 2**31 - 1):
                return False
        elif key == "config_id":
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                return False
        elif key == "dns_mode":
            if value not in ("off", "split", "full"):
                return False
        elif key == "dns_source":
            if value not in ("file", "manual"):
                return False
        elif key in ("dns_servers", "vpn_ipv4"):
            if not isinstance(value, list) or not 1 <= len(value) <= 8:
                return False
            try:
                if key == "dns_servers":
                    dns_addresses(value)
                else:
                    for address in value:
                        if not isinstance(address, str):
                            return False
                        parsed = ipaddress.IPv4Address(address)
                        if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
                            return False
            except (ValueError, DNSError):
                return False
    return True


@contextmanager
def probe_alarm(seconds):
    """Linux main-thread wall-clock cap, including slow/trickling HTTP headers."""
    def expired(*_):
        raise ProbeError("probe_budget_expired")
    try:
        old_handler = signal.signal(signal.SIGALRM, expired)
    except (ValueError, AttributeError):
        raise ProbeError("probe_deadline_unavailable") from None
    previous = signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous)
        signal.signal(signal.SIGALRM, old_handler)


@dataclass(frozen=True)
class Config:
    network_mode: str
    domains: tuple
    cidrs: tuple
    dns_mode: str
    dns_source: str
    manual_dns: tuple
    config_file: Path
    iface: str
    probe_name: str
    probe_url: str
    expected_status: int
    ca_file: Path | None

    @property
    def configured(self):
        return bool((self.domains or self.cidrs) and self.probe_name and self.probe_url)

    @property
    def identity(self):
        # A digest only: no probe URL/name, CA path or full configuration in status.
        return hashlib.sha256(repr(self).encode()).hexdigest()

    @classmethod
    def from_env(cls, env):
        mode = env.get("FEILIAN_NETWORK_MODE", "bridge")
        dns_mode = env.get("DNS_MODE", "auto")
        source = env.get("VPN_DNS_SOURCE", "file")
        if mode not in ("bridge", "macvlan", "host"):
            raise ConfigError("invalid_network_mode")
        if dns_mode not in ("auto", "split", "full", "off"):
            raise ConfigError("invalid_dns_mode")
        if mode == "host" and dns_mode != "off":
            raise ConfigError("host_requires_dns_off")
        if source not in ("file", "manual"):
            raise ConfigError("invalid_dns_source")
        try:
            domains = tuple(domain_name(value) for value in _split(env.get("CORP_DOMAINS", ""), 64, "invalid_corporate_domains"))
            manual = dns_addresses(_split(env.get("VPN_DNS", ""), 8, "invalid_dns_servers"))
        except DNSError as exc:
            raise ConfigError(str(exc)) from None
        if dns_mode == "split" and not domains:
            raise ConfigError("split_requires_corporate_domains")
        networks = []
        for value in _split(env.get("CORP_CIDRS", ""), 128, "invalid_corporate_cidrs"):
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError:
                raise ConfigError("invalid_corporate_cidrs") from None
            if (network.prefixlen == 0 or network.is_loopback or network.is_link_local
                    or network.is_multicast or network.network_address.is_unspecified):
                raise ConfigError("invalid_corporate_cidrs")
            networks.append(network)
        config_file = _absolute_path(env.get("VPN_CONFIG_FILE", "/opt/apps/com.volcengine.feilian/files/vpn.conf"), "invalid_vpn_config_path")
        iface = env.get("VPN_IFACE", "auto")
        if iface != "auto" and (not IFACE.fullmatch(iface) or iface == "lo"):
            raise ConfigError("invalid_vpn_interface")
        probe_name = env.get("VPN_PROBE_DNS_NAME", "")
        if probe_name:
            try:
                probe_name = domain_name(probe_name)
            except DNSError:
                raise ConfigError("invalid_probe_dns_name") from None
        url = env.get("VPN_PROBE_URL", "")
        if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
            raise ConfigError("invalid_probe_url")
        if url:
            try:
                parsed = urllib.parse.urlsplit(url)
                host = parsed.hostname
                if (parsed.scheme != "https" or not host or parsed.username is not None
                        or parsed.password is not None or parsed.fragment or "%" in parsed.netloc
                        or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
                    raise ValueError()
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    domain_name(host)
            except (ValueError, DNSError):
                raise ConfigError("invalid_probe_url") from None
        try:
            expected = int(env.get("VPN_PROBE_EXPECT_STATUS", "200"))
        except (TypeError, ValueError):
            raise ConfigError("invalid_expected_status") from None
        if not 200 <= expected <= 299:
            raise ConfigError("invalid_expected_status")
        ca = env.get("VPN_PROBE_CA_FILE", "")
        ca_file = _absolute_path(ca, "invalid_probe_ca_file") if ca else None
        if ca_file is not None:
            try:
                info = ca_file.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                    raise ValueError()
                with ca_file.open("rb") as stream:
                    stream.read(1)
            except (OSError, ValueError):
                raise ConfigError("invalid_probe_ca_file") from None
        if domains:
            if probe_name and not in_suffix(probe_name, domains):
                raise ConfigError("probe_outside_corporate_domain")
            if url:
                host = urllib.parse.urlsplit(url).hostname.lower().rstrip(".")
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if not in_suffix(host, domains):
                        raise ConfigError("probe_outside_corporate_domain")
        return cls(mode, domains, tuple(networks), dns_mode, source, manual, config_file,
                   iface, probe_name, url, expected, ca_file)


class StateStore:
    def __init__(self, directory="/run/feilian", clock=time):
        self.directory = Path(directory)
        self.clock = clock

    @property
    def draining(self):
        return (self.directory / "drain.request").exists() or (self.directory / "drain.request").is_symlink()

    def _write_lock(self):
        self.directory = secure_directory(self.directory)
        fd = os.open(self.directory / "status.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise DNSError("unsafe_status_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def publish(self, snapshot):
        fd = self._write_lock()
        try:
            if self.draining:
                snapshot = dict(snapshot, state="DRAINING", ready=False,
                                reason="draining", reasons=["draining"])
            atomic_write(self.directory, "status.json", json.dumps(snapshot, sort_keys=True).encode() + b"\n")
        finally:
            os.close(fd)
        return snapshot

    def drain(self):
        fd = self._write_lock()
        try:
            atomic_write(self.directory, "drain.request", b"draining\n")
            snapshot = make_status("DRAINING", "draining", self.clock.time())
            atomic_write(self.directory, "status.json", json.dumps(snapshot, sort_keys=True).encode() + b"\n")
            return snapshot
        finally:
            os.close(fd)

    def clear_drain(self):
        fd = self._write_lock()
        try:
            path = self.directory / "drain.request"
            if path.exists() or path.is_symlink():
                read_regular(path, 64)
                path.unlink()
        finally:
            os.close(fd)

    def read(self):
        # No mkdir, lock creation, probing or config reads on this path.
        try:
            if not self.directory.is_absolute() or ".." in self.directory.parts:
                raise ValueError()
            if any(parent.is_symlink() for parent in (self.directory, *self.directory.parents)):
                raise ValueError()
            directory_info = self.directory.stat()
            if directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o022:
                raise ValueError()
            raw, file_info = read_regular(self.directory / "status.json", 16384)
            if file_info.st_uid != os.geteuid() or file_info.st_mode & 0o022:
                raise ValueError()
            value = bounded_json(raw, 16384)
            keys = {"schema_version", "state", "live", "ready", "reason", "reasons", "updated_at", "evidence"}
            if not isinstance(value, dict) or set(value) != keys:
                raise ValueError()
            if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["state"] not in STATES:
                raise ValueError()
            if type(value["ready"]) is not bool or type(value["live"]) is not bool:
                raise ValueError()
            reasons = value["reasons"]
            if (not isinstance(reasons, list) or not 1 <= len(reasons) <= 16
                    or any(not isinstance(item, str) or not CODE.fullmatch(item) for item in reasons)
                    or value["reason"] != reasons[0]):
                raise ValueError()
            evidence = value["evidence"]
            if not valid_evidence(evidence):
                raise ValueError()
            updated = value["updated_at"]
            if type(updated) not in (float, int) or not math.isfinite(updated):
                raise ValueError()
            if value["ready"] and (value["state"] != "READY" or not value["live"]):
                raise ValueError()
            if value["state"] == "READY":
                required = {"interface", "vpn_ipv4", "dns_servers", "dns_source", "target_count",
                            "https_status", "success_count", "success_required", "config_id",
                            "dns_managed", "dns_active", "dns_mode"}
                if (not value["ready"] or not required <= set(evidence)
                        or evidence["success_count"] < evidence["success_required"]
                        or evidence["target_count"] < 1
                        or evidence["dns_managed"] and not evidence["dns_active"]
                        or evidence["dns_managed"] == (evidence["dns_mode"] == "off")):
                    raise ValueError()
            age = self.clock.time() - updated
            if age < -5 or age > TTL:
                return dict(value, state="DEGRADED" if value["state"] == "READY" else value["state"],
                            live=False, ready=False, reason="heartbeat_expired", reasons=["heartbeat_expired"])
            return value
        except FileNotFoundError:
            return make_status("DISCONNECTED", "status_missing", 0, live=False)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, DNSError):
            return make_status("DISCONNECTED", "status_invalid", 0, live=False)


def make_status(state, reason, now, evidence=None, live=True, extra_reasons=()):
    return {"schema_version": 1, "state": state, "live": bool(live),
            "ready": state == "READY" and bool(live), "reason": reason,
            "reasons": list(dict.fromkeys((reason, *extra_reasons)))[:16],
            "updated_at": now, "evidence": evidence or {}}


class CommandRunner:
    def run(self, args, timeout=2):
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


class DNSResolver:
    """Small bounded A-only DNS client; no system/public resolver fallback."""
    @staticmethod
    def _name(packet, offset):
        labels, seen, end = [], set(), None
        for _ in range(128):
            if offset >= len(packet) or offset in seen:
                raise ProbeError("dns_malformed_response")
            seen.add(offset)
            size = packet[offset]
            if size & 0xC0 == 0xC0:
                if offset + 1 >= len(packet):
                    raise ProbeError("dns_malformed_response")
                if end is None:
                    end = offset + 2
                offset = ((size & 0x3F) << 8) | packet[offset + 1]
                continue
            if size & 0xC0 or size > 63 or offset + 1 + size > len(packet):
                raise ProbeError("dns_malformed_response")
            offset += 1
            if size == 0:
                name = b".".join(labels).decode("ascii").lower()
                if len(name) > 253:
                    raise ProbeError("dns_malformed_response")
                return name, end if end is not None else offset
            labels.append(packet[offset:offset + size])
            offset += size
        raise ProbeError("dns_malformed_response")

    @classmethod
    def parse(cls, packet, query_id, name):
        if len(packet) < 12 or len(packet) > 65535:
            raise ProbeError("dns_malformed_response")
        ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        if ident != query_id or not flags & 0x8000 or flags & 0x780F or qd != 1 or an + ns + ar > 64:
            raise ProbeError("dns_malformed_response")
        if flags & 0x0200:
            raise ProbeError("dns_truncated_response")
        question, offset = cls._name(packet, 12)
        if question != name or packet[offset:offset + 4] != b"\x00\x01\x00\x01":
            raise ProbeError("dns_malformed_response")
        offset += 4
        addresses, aliases = {}, {}
        for index in range(an + ns + ar):
            owner, offset = cls._name(packet, offset)
            if offset + 10 > len(packet):
                raise ProbeError("dns_malformed_response")
            kind, klass, ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            if offset + length > len(packet):
                raise ProbeError("dns_malformed_response")
            if index < an and klass == 1 and ttl > 0:
                if kind == 1 and length == 4:
                    addresses.setdefault(owner, []).append(str(ipaddress.IPv4Address(packet[offset:offset + 4])))
                elif kind == 5:
                    target, consumed = cls._name(packet, offset)
                    if consumed != offset + length:
                        raise ProbeError("dns_malformed_response")
                    aliases[owner] = target
            offset += length
        current, seen = name, set()
        for _ in range(8):
            if current in seen:
                break
            seen.add(current)
            if current in addresses:
                return tuple(dict.fromkeys(addresses[current]))[:8]
            if current not in aliases:
                break
            current = aliases[current]
        raise ProbeError("enterprise_dns_no_ipv4_answer")

    def resolve(self, name, servers, timeout=2):
        name = domain_name(name)
        query_id = secrets.randbits(16)
        question = b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split(".")) + b"\x00\x00\x01\x00\x01"
        query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
        deadline = time.monotonic() + timeout
        for server in servers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(remaining)
                    sock.connect((server, 53))
                    sock.send(query)
                    packet = sock.recv(65536)
                try:
                    return self.parse(packet, query_id, name)
                except ProbeError as exc:
                    if str(exc) != "dns_truncated_response":
                        raise
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    sock.connect((server, 53))
                    sock.sendall(struct.pack("!H", len(query)) + query)
                    header = self._receive(sock, 2)
                    packet = self._receive(sock, struct.unpack("!H", header)[0])
                    return self.parse(packet, query_id, name)
            except (OSError, ValueError, UnicodeError, ProbeError):
                continue
        raise ProbeError("enterprise_dns_query_failed")

    @staticmethod
    def _receive(sock, size):
        result = bytearray()
        while len(result) < size:
            part = sock.recv(size - len(result))
            if not part:
                raise ProbeError("dns_malformed_response")
            result.extend(part)
        return bytes(result)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, pinned_ip, source_ip, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(host, source_address=(source_ip, 0), **kwargs)

    def connect(self):
        if self._tunnel_host:
            raise ProbeError("https_proxy_forbidden")
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class HTTPSProbe:
    def probe(self, url, address, source_ip, expected, ca_file=None, timeout=3):
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)

        class Handler(urllib.request.HTTPSHandler):
            def https_open(self, request):
                def connection(host, **kwargs):
                    return _PinnedConnection(host, pinned_ip=address, source_ip=source_ip,
                                             context=context, **kwargs)
                return self.do_open(connection, request)

        # ProxyHandler({}) is intentional: urllib otherwise trusts *_proxy env.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Handler(), _NoRedirect())
        request = urllib.request.Request(url, headers={"User-Agent": "feilian-readiness/1", "Connection": "close"})
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.getcode()
                if response.geturl() != url or status != expected or not 200 <= status <= 299:
                    raise ProbeError("https_unexpected_status")
                return status
        except urllib.error.HTTPError:
            raise ProbeError("https_unexpected_status") from None
        except (OSError, urllib.error.URLError, ssl.SSLError, ValueError, http.client.HTTPException):
            raise ProbeError("https_verification_failed") from None


class Controller:
    def __init__(self, config, store=None, runner=None, clock=time, resolver=None,
                 https_probe=None, dns_manager=None, success_required=2, config_max_age=CONFIG_MAX_AGE,
                 config_error=None):
        self.config = config
        self.clock = clock
        self.store = store or StateStore(clock=clock)
        self.runner = runner or CommandRunner()
        self.resolver = resolver or DNSResolver()
        self.https = https_probe or HTTPSProbe()
        self.dns = dns_manager if dns_manager is not None else (
            DNSManager(self.store.directory, network_mode=config.network_mode,
                       forwarder=os.environ.get("FEILIAN_DNS_FORWARDER", "1") == "1") if config else None)
        if not 1 <= success_required <= 10:
            raise ValueError("success_required must be 1..10")
        self.success_required = success_required
        self.config_max_age = config_max_age
        self.config_error = config_error
        self.successes = 0
        self.ever_ready = False
        self.tunnel_seen = False
        self.deadline = 0
        previous = self.store.read()
        if config and previous["live"] and previous["evidence"].get("config_id") == config.identity:
            old = previous["evidence"].get("success_count", 0)
            if type(old) is int and 0 <= old <= success_required:
                self.successes = old
                self.ever_ready = previous["ready"]

    def _timeout(self, limit=2):
        remaining = self.deadline - self.clock.monotonic()
        if remaining <= 0:
            raise ProbeError("probe_budget_expired")
        return max(0.001, min(limit, remaining))

    def _ip_json(self, args):
        try:
            result = self.runner.run(["ip", "-j", *args], timeout=self._timeout())
            if result.returncode:
                raise ValueError()
            value = bounded_json(result.stdout, 65536)
            if not isinstance(value, list) or len(value) > 32:
                raise ValueError()
            return value
        except (OSError, ValueError, TypeError, RecursionError, subprocess.TimeoutExpired):
            raise ProbeError("route_probe_failed") from None

    def _route(self, address):
        result = self._ip_json(["route", "get", str(address)])
        if len(result) != 1 or not isinstance(result[0], dict):
            raise ProbeError("target_not_routed_via_vpn")
        route = result[0]
        dev = route.get("dev")
        if (not isinstance(dev, str) or not IFACE.fullmatch(dev) or dev == "lo"
                or route.get("type", "unicast") != "unicast"):
            raise ProbeError("target_not_routed_via_vpn")
        return route

    def _interface(self, interface):
        links = self._ip_json(["link", "show", "dev", interface])
        addresses = self._ip_json(["address", "show", "dev", interface])
        if len(links) != 1 or len(addresses) != 1:
            raise ProbeError("vpn_interface_inactive")
        link = links[0]
        if not isinstance(link, dict) or not isinstance(addresses[0], dict):
            raise ProbeError("vpn_interface_inactive")
        flags = link.get("flags", [])
        kind = link.get("linkinfo", {}).get("info_kind", "") if isinstance(link.get("linkinfo", {}), dict) else ""
        if not isinstance(flags, list) or "UP" not in flags or link.get("operstate") in ("DOWN", "LOWERLAYERDOWN", "NOTPRESENT"):
            raise ProbeError("vpn_interface_inactive")
        # Route evidence chooses the interface, not a tun* name heuristic. Require
        # tunnel characteristics too; an explicit eth0 is not a VPN certificate.
        if "POINTOPOINT" not in flags and kind not in ("tun", "tap", "wireguard", "ppp", "ipip", "gre", "gretap", "vti", "xfrm"):
            raise ProbeError("vpn_interface_not_tunnel")
        result = []
        entries = addresses[0].get("addr_info", [])
        if not isinstance(entries, list) or len(entries) > 32:
            raise ProbeError("vpn_interface_inactive")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("family") != "inet" or entry.get("scope", "global") != "global":
                continue
            try:
                address = ipaddress.IPv4Address(entry.get("local"))
            except (ValueError, TypeError):
                continue
            if not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
                result.append(str(address))
        if not result:
            raise ProbeError("vpn_interface_no_ipv4")
        return tuple(dict.fromkeys(result))[:8]

    def _read_dns(self):
        if self.config.dns_source == "manual":
            if not self.config.manual_dns:
                raise ProbeError("vpn_dns_missing")
            return self.config.manual_dns, None
        try:
            raw, info = read_regular(self.config.config_file, 65536)
            age = self.clock.time() - info.st_mtime
            if age < -5:
                raise ProbeError("vpn_config_timestamp_invalid")
            value = bounded_json(raw)
            if not isinstance(value, dict) or "DNS" not in value:
                raise ValueError()
            servers = dns_addresses(value["DNS"])
            if not servers:
                raise ValueError()
            return servers, max(0, int(age))
        except FileNotFoundError:
            raise ProbeError("vpn_config_missing") from None
        except (OSError, ValueError, TypeError, RecursionError, DNSError):
            raise ProbeError("vpn_config_invalid") from None

    def _targets(self, addresses):
        if not isinstance(addresses, (list, tuple)) or not 1 <= len(addresses) <= 8:
            raise ProbeError("enterprise_dns_no_ipv4_answer")
        result = []
        for value in addresses:
            try:
                address = ipaddress.IPv4Address(value)
            except (ValueError, TypeError):
                raise ProbeError("enterprise_dns_no_ipv4_answer") from None
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise ProbeError("probe_target_not_corporate")
            networks = self.config.cidrs or INTERNAL_V4
            if not any(address.version == network.version and address in network for network in networks):
                raise ProbeError("probe_target_not_corporate")
            result.append(str(address))
        return tuple(dict.fromkeys(result))

    def _probe(self, evidence):
        servers, age = self._read_dns()
        evidence.update(dns_servers=list(servers), dns_source=self.config.dns_source)
        if age is not None:
            evidence["dns_age_seconds"] = age
            evidence["dns_config_stale"] = age > self.config_max_age
        first = self._route(servers[0])
        interface = first["dev"]
        if self.config.iface != "auto" and interface != self.config.iface:
            raise ProbeError("target_not_routed_via_vpn")
        addresses = self._interface(interface)
        self.tunnel_seen = True
        ifindex = None
        links = self._ip_json(["link", "show", "dev", interface])
        if len(links) == 1 and isinstance(links[0], dict):
            candidate = links[0].get("ifindex")
            if type(candidate) is int and candidate > 0:
                ifindex = candidate
        evidence.update(interface=interface, vpn_ipv4=list(addresses),
                        interface_ifindex=ifindex)
        for server in servers:
            if self._route(server)["dev"] != interface:
                raise ProbeError("dns_not_routed_via_vpn")
        answers = self._targets(self.resolver.resolve(self.config.probe_name, servers, timeout=self._timeout(3)))
        host = urllib.parse.urlsplit(self.config.probe_url).hostname.lower().rstrip(".")
        try:
            target_addresses = self._targets((str(ipaddress.ip_address(host)),))
        except ValueError:
            target_addresses = answers if host == self.config.probe_name else self._targets(
                self.resolver.resolve(host, servers, timeout=self._timeout(3)))
        targets = tuple(dict.fromkeys((*answers, *target_addresses)))
        source = addresses[0]
        for target in targets:
            route = self._route(target)
            if route["dev"] != interface:
                raise ProbeError("target_not_routed_via_vpn")
            selected = route.get("prefsrc", route.get("src"))
            if selected is not None and selected not in addresses:
                raise ProbeError("vpn_source_address_mismatch")
            if target == target_addresses[0] and selected:
                source = selected
        evidence["target_count"] = len(targets)
        status = self.https.probe(self.config.probe_url, target_addresses[0], source,
                                 self.config.expected_status, self.config.ca_file, timeout=self._timeout(3))
        if type(status) is not int or status != self.config.expected_status or not 200 <= status <= 299:
            raise ProbeError("https_unexpected_status")
        evidence["https_status"] = status
        # Check route/interface again after HTTPS, not just before the handshake.
        if self._interface(interface) != addresses or any(self._route(target)["dev"] != interface for target in (*servers, *targets)):
            raise ProbeError("target_not_routed_via_vpn")
        return servers

    def once(self):
        if self.store.draining:
            return self.store.publish(make_status("DRAINING", "draining", self.clock.time()))
        self.deadline = self.clock.monotonic() + PROBE_BUDGET
        evidence = {"success_count": 0, "success_required": self.success_required}
        success, servers, reasons = False, (), []
        if self.config is None:
            state, reason = "UNCONFIGURED", self.config_error or "configuration_invalid"
        elif not self.config.configured:
            evidence["config_id"] = self.config.identity
            state, reason = "UNCONFIGURED", "corporate_probe_not_configured"
        else:
            evidence["config_id"] = self.config.identity
            try:
                with probe_alarm(self._timeout(PROBE_BUDGET)):
                    servers = self._probe(evidence)
                success = True
                state, reason = "VALIDATING", "success_threshold_pending"
            except ProbeError as exc:
                reason = str(exc)
                if self.ever_ready and reason in ("vpn_config_missing", "vpn_dns_missing", "vpn_interface_inactive", "target_not_routed_via_vpn", "route_probe_failed"):
                    state = "DISCONNECTED"
                else:
                    state = "DEGRADED" if self.tunnel_seen else "WAITING_AUTH"
            except (OSError, ValueError, TypeError, KeyError, AttributeError, DNSError):
                state, reason = "DEGRADED", "probe_invalid_result"
        if self.config is not None and self.dns is not None:
            # The DNS owner binds every VPN upstream to the observed tunnel
            # interface and its kernel index, so a stale connection cannot resolve
            # corporate names through the bootstrap route. Both are therefore
            # required evidence on the connected path, not optional decoration.
            interface = evidence.get("interface") if success else ""
            ifindex = evidence.get("interface_ifindex") if success else None
            if success and (not interface or type(ifindex) is not int or ifindex <= 0):
                success, state, reason = False, "DEGRADED", "vpn_interface_inactive"
                interface, ifindex = "", None
            try:
                dns = self.dns.apply(success, servers, self.config.domains, self.config.dns_mode,
                                     vpn_interface=interface or "", vpn_ifindex=ifindex)
                evidence.update(dns_managed=dns["managed"], dns_active=dns["active"], dns_mode=dns["mode"])
                if success and dns["managed"] and not dns["active"]:
                    success, state, reason = False, "DEGRADED", "dnsmasq_not_running"
            except (DNSError, OSError, ValueError, TypeError, KeyError):
                reasons.append(reason)
                success, state, reason = False, "DEGRADED", "dns_configuration_failed"
        if success:
            self.successes = min(self.success_required, self.successes + 1)
            if self.successes >= self.success_required:
                state, reason = "READY", "all_probes_passed"
                self.ever_ready = True
        else:
            self.successes = 0
        evidence["success_count"] = self.successes
        return self.store.publish(make_status(state, reason, self.clock.time(), evidence, extra_reasons=reasons))

    def run(self, interval=5):
        stop = False

        def stopping(*_):
            nonlocal stop
            stop = True
            # Signal handler only requests a stop; the supervisor may also use
            # the separate drain command for immediate atomic withdrawal.

        old = {sig: signal.signal(sig, stopping) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.store.clear_drain()
            while not stop:
                self.once()
                self.clock.sleep(interval)
        finally:
            self.store.drain()
            self.store.publish(make_status("DRAINING", "draining", self.clock.time(), live=False))
            if self.dns is not None:
                self.dns.restore()
                self.dns.close()
            for sig, handler in old.items():
                signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "once", "status", "check", "drain"))
    parser.add_argument("--state-dir", default="/run/feilian")
    parser.add_argument("--kind", choices=("ready", "live"), default="ready", help="check predicate")
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args(argv)
    store = StateStore(args.state_dir)
    if args.command in ("status", "check"):
        snapshot = store.read()
        print(json.dumps(snapshot, sort_keys=True))
        return int(not snapshot[args.kind]) if args.command == "check" else 0
    try:
        if args.command == "drain":
            print(json.dumps(store.drain(), sort_keys=True))
            return 0
        if not math.isfinite(args.interval) or not 0.1 <= args.interval <= 5:
            raise ConfigError("invalid_poll_interval")
        directory = secure_directory(args.state_dir)
        fd = os.open(directory / "controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise DNSError("unsafe_controller_lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigError("controller_already_running") from None
            try:
                config, error = Config.from_env(os.environ), None
            except ConfigError as exc:
                config, error = None, str(exc)
            controller = Controller(config, store=store, config_error=error)
            try:
                if args.command == "once":
                    print(json.dumps(controller.once(), sort_keys=True))
                else:
                    controller.run(args.interval)
            finally:
                if controller.dns is not None:
                    controller.dns.close()
        finally:
            os.close(fd)
        return 0
    except (OSError, DNSError, ConfigError) as exc:
        # Never emit filesystem contents, URLs, raw command output or secrets.
        code = str(exc) if CODE.fullmatch(str(exc)) else "runtime_operation_failed"
        print(json.dumps({"error": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
