#!/usr/bin/env python3
"""Container-private, single-owner dnsmasq configuration (standard library).

Never starts a daemon or modifies routes/rules/sysctls. The supervisor starts
``dnsmasq --no-daemon --conf-file=<state_dir>/dnsmasq.conf``. Only servers-file
changes dynamically: dnsmasq rereads it AND flushes its cache on SIGHUP; the main
configuration is not reread on SIGHUP.

Split mode retains local-only corporate suffix rules while disconnected: these
names never fall through to public bootstrap DNS. Full mode deliberately restores
bootstrap DNS while disconnected for GUI authentication, still blocking explicitly
configured corporate suffixes. Without suffixes, full mode cannot identify names
to block offline. This authentication exception is not a general DNS kill-switch.
Host requires off: no writes and no requested port-53 listener.

resolv.conf is written in place, preserving Docker's bind-mounted inode. Ownership
checks inode AND content; later third-party edits are never overwritten. Tests
must inject temporary paths, a syntax-check runner and a reloader. Defaults are
ONLY for the container's private filesystem/network namespace.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import tempfile
import uuid

MAX_FILE = 65536
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")


class DNSError(Exception):
    """Fixed non-secret error code, safe to put in status."""


def domain_name(value: str) -> str:
    if not isinstance(value, str):
        raise DNSError("invalid_corporate_domain")
    name = value.lower().rstrip(".")
    if not _DOMAIN.fullmatch(name) or "." not in name:
        raise DNSError("invalid_corporate_domain")
    return name


def dns_addresses(values) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > 8:
        raise DNSError("invalid_dns_servers")
    result = []
    for value in values:
        if not isinstance(value, str) or "%" in value:
            raise DNSError("invalid_dns_servers")
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            raise DNSError("invalid_dns_servers") from None
        if addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_loopback:
            raise DNSError("invalid_dns_servers")
        if str(addr) not in result:
            result.append(str(addr))
    return tuple(result)


def secure_directory(path) -> Path:
    """Require an absolute non-symlink directory, including every ancestor."""
    path = Path(path)
    if (not path.is_absolute() or ".." in path.parts or len(str(path)) > 4096
            or any(ord(character) < 33 for character in str(path))):
        raise DNSError("unsafe_state_directory")
    for current in reversed((path, *path.parents)):
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise DNSError("unsafe_state_directory")
        else:
            current.mkdir(mode=0o700)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise DNSError("unsafe_state_directory")
    return path


def read_regular(path: Path, limit=MAX_FILE) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise DNSError("invalid_private_file")
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns
        ) or len(data) != after.st_size:
            raise DNSError("unstable_private_file")
        return data, after
    finally:
        os.close(fd)


def atomic_write(directory: Path, name: str, content: bytes) -> None:
    """No destination symlink; temporary file and replace stay in directory."""
    if not name or Path(name).name != name or name in (".", ".."):
        raise DNSError("unsafe_private_filename")
    target = directory / name
    if target.is_symlink():
        raise DNSError("unsafe_private_file")
    fd, temporary = tempfile.mkstemp(prefix=".feilian-", dir=directory)
    temporary = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists() and temporary.parent == directory:
            temporary.unlink()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SyntaxRunner:
    def run(self, args, timeout=3):
        return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})


class PidReloader:
    """Signal only dnsmasq in this netns, using the exact owned --conf-file."""
    def __init__(self, pid_file: Path, conf_file: Path):
        self.pid_file = pid_file
        self.conf_file = conf_file

    def _pid(self):
        try:
            raw, _ = read_regular(self.pid_file, 32)
            if not re.fullmatch(rb"[1-9][0-9]{0,9}\n?", raw):
                return None
            pid = int(raw)
            if pid <= 1 or pid > 2147483647:
                return None
            proc = Path("/proc") / str(pid)
            if Path(os.readlink(proc / "exe")).name != "dnsmasq":
                return None
            if (proc / "ns/net").stat().st_ino != Path("/proc/self/ns/net").stat().st_ino:
                return None
            with (proc / "cmdline").open("rb") as stream:
                args = stream.read(8193).split(b"\0")
            expected = os.fsencode(str(self.conf_file))
            if b"--conf-file=" + expected not in args and not any(
                args[i] in (b"-C", b"--conf-file") and args[i + 1] == expected
                for i in range(len(args) - 1)
            ):
                return None
            return pid
        except (OSError, ValueError, DNSError):
            return None

    def active(self) -> bool:
        return self._pid() is not None

    def reload(self) -> None:
        pid = self._pid()
        if pid is None:
            raise DNSError("dnsmasq_pid_unverified")
        handle = None
        try:
            if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                handle = os.pidfd_open(pid)
                if self._pid() != pid:
                    raise DNSError("dnsmasq_pid_unverified")
                signal.pidfd_send_signal(handle, signal.SIGHUP)
            else:
                if self._pid() != pid:
                    raise DNSError("dnsmasq_pid_unverified")
                os.kill(pid, signal.SIGHUP)
        except OSError:
            raise DNSError("dnsmasq_reload_failed") from None
        finally:
            if handle is not None:
                os.close(handle)


class DNSManager:
    def __init__(self, state_dir="/run/feilian", resolv_path="/etc/resolv.conf",
                 runner=None, reloader=None, network_mode="bridge", ifindex_resolver=None):
        self.ifindex_resolver = ifindex_resolver or socket.if_nametoindex
        self.state_dir = Path(state_dir)
        self.resolv_path = Path(resolv_path)
        self.network_mode = network_mode
        self.runner = runner or SyntaxRunner()
        self.reloader = reloader or PidReloader(self.state_dir / "dnsmasq.pid",
                                               self.state_dir / "dnsmasq.conf")
        self._lock_fd = None
        self._record = None

    @property
    def conf_path(self):
        return self.state_dir / "dnsmasq.conf"

    def _save_record(self):
        atomic_write(self.state_dir, "dns-owner.json",
                     json.dumps(self._record, sort_keys=True).encode() + b"\n")

    def _acquire(self):
        if self._lock_fd is not None:
            return
        self.state_dir = secure_directory(self.state_dir)
        fd = os.open(self.state_dir / "dns-owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise DNSError("unsafe_dns_lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd = fd
        except (OSError, DNSError):
            os.close(fd)
            raise DNSError("dns_owner_busy") from None
        try:
            current, info = read_regular(self.resolv_path, 16384)
            owner_path = self.state_dir / "dns-owner.json"
            if owner_path.exists() or owner_path.is_symlink():
                raw, _ = read_regular(owner_path, MAX_FILE)
                record = json.loads(raw)
                if (not isinstance(record, dict) or record.get("schema_version") != 1
                        or record.get("resolv_path") != str(self.resolv_path)
                        or record.get("inode") != [info.st_dev, info.st_ino]
                        or digest(current) not in (record.get("original_hash"), record.get("owned_hash"))):
                    raise DNSError("dns_owner_conflict")
                original = base64.b64decode(record["original"], validate=True)
                if len(original) > 16384 or digest(original) != record["original_hash"]:
                    raise DNSError("dns_owner_conflict")
                if not isinstance(record.get("files"), dict):
                    raise DNSError("dns_owner_conflict")
                self._record = record
            else:
                if any((self.state_dir / name).exists() or (self.state_dir / name).is_symlink()
                       for name in ("dnsmasq.conf", "dnsmasq.servers")):
                    raise DNSError("dns_owner_conflict")
                self._record = {"schema_version": 1, "owner": uuid.uuid4().hex,
                                "resolv_path": str(self.resolv_path),
                                "inode": [info.st_dev, info.st_ino],
                                "original": base64.b64encode(current).decode(),
                                "original_hash": digest(current), "owned_hash": None,
                                "files": {}}
                self._save_record()
        except (OSError, ValueError, KeyError, TypeError, DNSError):
            self.close()
            raise DNSError("dns_owner_conflict") from None

    def _bootstrap(self):
        original = base64.b64decode(self._record["original"], validate=True).decode("utf-8", "replace")
        servers = []
        for line in original.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) == 2 and parts[0] == "nameserver":
                try:
                    address = ipaddress.ip_address(parts[1])
                except ValueError:
                    continue
                # Docker's embedded bootstrap resolver is a deliberate exception.
                if address.is_unspecified or address.is_multicast or str(address) == "127.0.0.1":
                    continue
                if str(address) not in servers:
                    servers.append(str(address))
        if len(servers) > 8:
            raise DNSError("too_many_bootstrap_servers")
        return servers

    def _in_place(self, content, allowed):
        fd = os.open(self.resolv_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or [info.st_dev, info.st_ino] != self._record["inode"]:
                raise DNSError("resolv_ownership_lost")
            current = os.read(fd, 16385)
            if len(current) > 16384 or digest(current) not in allowed:
                raise DNSError("resolv_ownership_lost")
            os.lseek(fd, 0, os.SEEK_SET)
            view = memoryview(content)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise DNSError("resolv_write_failed")
                view = view[count:]
            os.ftruncate(fd, len(content))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _owned_file(self, name):
        path = self.state_dir / name
        expected = self._record["files"].get(name)
        if not path.exists() and not path.is_symlink():
            if expected is not None:
                raise DNSError("dns_config_ownership_lost")
            return None
        current, _ = read_regular(path)
        if expected is None or digest(current) != expected:
            raise DNSError("dns_config_ownership_lost")
        return current

    def _validate(self, main: bytes, servers: bytes):
        server_fd, server_name = tempfile.mkstemp(prefix=".dns-servers-", dir=self.state_dir)
        main_fd, main_name = tempfile.mkstemp(prefix=".dns-main-", dir=self.state_dir)
        try:
            with os.fdopen(server_fd, "wb") as stream:
                stream.write(servers)
            candidate = main.replace(os.fsencode(str(self.state_dir / "dnsmasq.servers")),
                                     os.fsencode(server_name))
            with os.fdopen(main_fd, "wb") as stream:
                stream.write(candidate)
            result = self.runner.run(["dnsmasq", "--test", "--conf-file=" + main_name], timeout=3)
            if result.returncode != 0:
                raise DNSError("dns_syntax_rejected")
        except (OSError, subprocess.TimeoutExpired):
            raise DNSError("dns_syntax_check_failed") from None
        finally:
            for name in (server_name, main_name):
                path = Path(name)
                if path.parent == self.state_dir and path.exists():
                    path.unlink()

    def _check_generation(self, interface, ifindex):
        if (not isinstance(interface, str) or not _INTERFACE.fullmatch(interface) or interface == "lo"
                or type(ifindex) is not int or not 1 <= ifindex <= 2147483647):
            raise DNSError("invalid_vpn_dns_interface")
        try:
            current = self.ifindex_resolver(interface)
        except (OSError, ValueError):
            raise DNSError("vpn_dns_interface_unavailable") from None
        if type(current) is not int or current != ifindex:
            raise DNSError("vpn_dns_interface_generation_changed")

    def apply(self, connected: bool, dns_servers=(), domains=(), mode="auto", *,
              vpn_interface="", vpn_ifindex=None) -> dict:
        if mode not in ("auto", "split", "full", "off") or self.network_mode not in ("bridge", "macvlan", "host"):
            raise DNSError("invalid_dns_mode")
        if self.network_mode == "host" and mode != "off":
            raise DNSError("host_requires_dns_off")
        if mode == "off":
            return {"managed": False, "active": False, "mode": "off"}
        domains = tuple(dict.fromkeys(domain_name(domain) for domain in domains))
        if len(domains) > 64:
            raise DNSError("too_many_corporate_domains")
        mode = ("split" if domains else "full") if mode == "auto" else mode
        if mode == "split" and not domains:
            raise DNSError("split_requires_corporate_domains")
        vpn = dns_addresses(dns_servers)
        if connected and not vpn:
            raise DNSError("vpn_dns_missing")
        generation = [vpn_interface, vpn_ifindex] if connected else None
        if connected:
            self._check_generation(vpn_interface, vpn_ifindex)
        self._acquire()
        bootstrap = self._bootstrap()
        if (not connected or mode == "split") and not bootstrap:
            raise DNSError("bootstrap_dns_missing")
        main = ("# Owned by feilian; dynamic data is ONLY in servers-file.\n"
                "port=53\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\n"
                # The private state directory and server snapshots are root-only;
                # HUP must retain permission to reread the atomically replaced file.
                "user=root\ncache-size=150\n"
                f"pid-file={self.state_dir / 'dnsmasq.pid'}\n"
                f"servers-file={self.state_dir / 'dnsmasq.servers'}\n").encode()
        lines = ["# Owned by feilian; SIGHUP rereads this file and clears the cache."]
        general = vpn if connected and mode == "full" else bootstrap
        lines.extend("server=" + address for address in general)
        for domain in domains:
            if connected:
                lines.extend(f"server=/{domain}/{address}" for address in vpn)
            else:
                lines.append(f"server=/{domain}/")
        servers = ("\n".join(lines) + "\n").encode()
        old_main = self._owned_file("dnsmasq.conf")
        old_servers = self._owned_file("dnsmasq.servers")
        if old_main is not None and old_main != main:
            raise DNSError("dns_main_requires_restart")
        changed = old_main != main or old_servers != servers
        if changed:
            self._validate(main, servers)
            self._record["files"] = {"dnsmasq.conf": digest(main), "dnsmasq.servers": digest(servers)}
            self._save_record()
            atomic_write(self.state_dir, "dnsmasq.servers", servers)
            atomic_write(self.state_dir, "dnsmasq.conf", main)
        active = self.reloader.active()
        if changed and active:
            try:
                self.reloader.reload()
            except (DNSError, OSError):
                if old_servers is not None:
                    atomic_write(self.state_dir, "dnsmasq.servers", old_servers)
                    self._record["files"]["dnsmasq.servers"] = digest(old_servers)
                    self._save_record()
                    try:
                        self.reloader.reload()
                    except (DNSError, OSError):
                        pass
                raise DNSError("dnsmasq_reload_failed") from None
        # Before independently supervised daemon startup preserve bootstrap DNS.
        if active:
            owned = (f"# feilian DNS owner {self._record['owner']}\n"
                     "nameserver 127.0.0.1\noptions timeout:2 attempts:2\n").encode()
            previous_owned = self._record["owned_hash"]
            self._record["owned_hash"] = digest(owned)
            self._save_record()
            self._in_place(owned, {self._record["original_hash"], previous_owned, digest(owned)})
        return {"managed": True, "active": bool(active), "mode": mode}

    def restore(self) -> bool:
        """Restore only our still-current resolver; leave later edits alone."""
        if self._record is None:
            return False
        owned = self._record.get("owned_hash")
        if owned is None:
            return False
        try:
            current, info = read_regular(self.resolv_path, 16384)
            if [info.st_dev, info.st_ino] != self._record["inode"] or digest(current) != owned:
                return False
            original = base64.b64decode(self._record["original"], validate=True)
            self._in_place(original, {owned})
            return True
        except (OSError, ValueError, DNSError):
            return False

    def close(self):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


__all__ = ["DNSManager", "DNSError", "PidReloader", "atomic_write", "read_regular",
           "secure_directory", "domain_name", "dns_addresses"]
