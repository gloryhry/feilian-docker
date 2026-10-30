#!/usr/bin/env python3
"""PID 1 supervisor for the isolated FeiLian runtime.

Owns process groups, bounded restarts and the readiness-linked data plane so that
"the container is up" never implies "the enterprise network is reachable".

Ordering rules enforced here:
  * bootstrap (dbus, Xvfb/x11vnc/noVNC, nginx, service, GUI) -> always, and it is
    independent of VPN state, so a user can always authenticate in the browser.
  * DNS controller -> only in isolated modes (bridge/macvlan); host mode never
    touches the resolver.
  * data plane (nft guard -> proxy prepare -> microsocks/privoxy) only after the
    VPN controller reports READY; any loss of readiness tears the data plane down
    *before* anything else so a stale socket can never fall back to the bootstrap
    route.

Nothing here reads secret contents, and no configuration is sourced or evaluated.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path("/opt/feilian")
RUNTIME = ROOT / "runtime"
STATE_DIR = Path("/run/feilian")
WEB_DIR = Path("/run/feilian-web")
PROXY_DIR = Path("/run/feilian-proxy")
SECRETS_DIR = Path("/run/feilian-secrets")
LOG_DIR = Path("/var/log/feilian")
APP_DIR = Path("/opt/apps/com.volcengine.feilian/files")
GUI_USER = "feilian"
SOCKS_USER = "feilian-socks"
HTTP_USER = "feilian-http"
STATE_SCHEMA = 1
STATE_MAX_AGE = 60.0
MAX_CONTEXT = 128 * 1024
CRITICAL = ("service",)


class SupervisorError(Exception):
    pass


def _atomic_json(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise SupervisorError("refusing symlinked runtime state")
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".runtime-", suffix=".part", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None and temporary.parent == path.parent:
            temporary.unlink(missing_ok=True)


def _atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise SupervisorError("refusing symlinked runtime file")
    fd, name = tempfile.mkstemp(prefix=".runtime-", suffix=".part", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None and temporary.parent == path.parent:
            temporary.unlink(missing_ok=True)


def read_json(path: Path, limit: int = MAX_CONTEXT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SupervisorError("state must be a regular file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise SupervisorError("state exceeds size limit")
    return json.loads(raw.decode("utf-8"))


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class Process:
    """One supervised child in its own session/process group."""

    def __init__(self, name, argv, *, user="", env_extra=None, log="", required=False,
                 pid_file=None):
        self.name, self.argv, self.user = name, list(argv), user
        # dnsmasq --no-daemon never writes its own pid file, but the DNS owner
        # verifies and HUPs by pid; the supervisor, as the parent, publishes it.
        self.pid_file = Path(pid_file) if pid_file else None
        self.env_extra = dict(env_extra or {})
        self.log = LOG_DIR / (log or name + ".log")
        self.required = required
        self.pid = 0
        self.started_at = 0.0
        self.failures = 0
        self.next_try = 0.0
        self.handle = None

    def alive(self) -> bool:
        return bool(self.pid) and pid_alive(self.pid)

    def start(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        command = self.argv
        if self.user:
            command = ["runuser", "-u", self.user, "--", *self.argv]
        environment = {**os.environ, **self.env_extra}
        # Each wrapper process keeps a bounded log on the log volume. Sending child
        # output to /dev/null used to make "proxy did not come up" undiagnosable.
        # Official client logs stay on the named volume and are never tailed to
        # stdout by default.
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log = open(self.log, "ab", buffering=0)
        # The child gets its own session: killpg() then reaps helper processes too.
        self.handle = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=self._log, stderr=self._log,
            start_new_session=True, env=environment, cwd="/",
        )
        self.pid = self.handle.pid
        self.started_at = time.time()
        if self.pid_file is not None:
            _atomic_text(self.pid_file, f"{self.pid}\n", mode=0o600)

    def poll(self):
        if self.handle is None:
            return None
        return self.handle.poll()

    def stop(self, timeout: float = 8.0) -> None:
        if not self.pid:
            return
        group = self.pid
        for sig, wait in ((signal.SIGTERM, timeout), (signal.SIGKILL, 3.0)):
            try:
                os.killpg(group, sig)
            except ProcessLookupError:
                self.pid = 0
                return
            except PermissionError:
                pass
            deadline = time.time() + wait
            while time.time() < deadline:
                code = self.poll()
                if code is not None:
                    self._reap()
                    return
                time.sleep(0.1)
        self._reap()

    def _reap(self):
        handle = getattr(self, "_log", None)
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
            self._log = None
        if self.handle is not None:
            try:
                self.handle.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        self.pid = 0
        self.handle = None


class Supervisor:
    def __init__(self, env=None, state_dir=STATE_DIR, runtime_dir=RUNTIME):
        self.env = dict(os.environ if env is None else env)
        self.state_dir = Path(state_dir)
        self.runtime_dir = Path(runtime_dir)
        self.mode = self.env.get("FEILIAN_NETWORK_MODE", "bridge")
        if self.mode not in ("bridge", "macvlan", "host"):
            raise SupervisorError("unsupported network mode")
        self.managed = self.mode != "host"
        self.procs: dict[str, Process] = {}
        self.stop_requested = False
        self.draining = False
        self.data_plane = "closed"
        self.controller_ready = False
        self.notes: list[str] = []

    # ------------------------------------------------------------- processes
    def register(self, name, argv, **kwargs):
        self.procs[name] = Process(name, argv, **kwargs)

    def _bootstrap_plan(self):
        gui = self.env.get("GUI_MODE", "vnc")
        geometry = self.env.get("VNC_GEOMETRY", "1600x1000x24")
        vnc_port = self.env.get("VNC_PORT", "5900")
        internal = self.env.get("NOVNC_INTERNAL_PORT", "6080")
        if self.env.get("START_SERVICE", "1") == "1":
            self.register("service", [str(APP_DIR / "corplink-service")],
                          log="corplink-service.log", required=True)
        if gui == "x11":
            display = self.env.get("X11_DISPLAY", ":0")
        else:
            display = ":" + self.env.get("DISPLAY_NUM", "99")
            self.register("xvfb", ["Xvfb", display, "-screen", "0", geometry,
                                   "-nolisten", "tcp", "-ac", "+extension", "RANDR"],
                          log="xvfb.log")
            vnc_args = ["x11vnc", "-display", display, "-forever", "-shared",
                        "-rfbport", vnc_port, "-localhost", "-quiet", "-noxdamage"]
            password = SECRETS_DIR / "vnc.pass"
            vnc_args += ["-rfbauth", str(password)] if password.exists() else ["-nopw"]
            self.register("x11vnc", vnc_args, log="x11vnc.log")
            sock = WEB_DIR / "novnc.sock"
            self.register("websockify", [
                "websockify", "--unix-listen=" + str(sock), "--unix-listen-mode=0660",
                "--web=/usr/share/novnc", f"127.0.0.1:{vnc_port}"], log="novnc.log")
        self.register("nginx", ["nginx", "-c", str(WEB_DIR / "nginx.conf")], log="nginx.log")
        if self.env.get("START_GUI", "1") == "1":
            self.register("gui", [str(APP_DIR / "corplink")], user=GUI_USER, log="corplink-gui.log",
                          env_extra={
                              "HOME": "/home/feilian", "DISPLAY": display,
                              "XDG_RUNTIME_DIR": "/run/user/1000",
                              "ELECTRON_DISABLE_SECURITY_WARNINGS": "1",
                              "FEILIAN_GUI_ARGS": self.env.get("EXTRA_GUI_ARGS",
                                  "--disable-gpu --disable-dev-shm-usage")})
        if self.managed:
            self.register("controller", [sys.executable, str(self.runtime_dir / "vpn_state.py"),
                                        "run", "--state-dir", str(self.state_dir)],
                          log="vpn-controller.log")
            dns_args = ["dnsmasq", "--no-daemon",
                        "--conf-file=" + str(self.state_dir / "dnsmasq.conf")]
            # Opt-in query tracing: off by default (privacy and volume), but the
            # only way to see whether a resolver actually received/forwarded a query.
            if self.env.get("FEILIAN_DNS_DEBUG", "0") == "1":
                dns_args += ["--log-queries", "--log-facility=-"]
            self.register("dnsmasq", dns_args, log="dnsmasq.log",
                          pid_file=self.state_dir / "dnsmasq.pid")

    def _sensitive(self, name):
        return name in ("controller", "dnsmasq", "guard", "microsocks", "privoxy")

    def sync_processes(self):
        now = time.time()
        for name, proc in self.procs.items():
            if self.draining and name not in ("guard",):
                continue
            code = proc.poll()
            if code is not None and proc.pid:
                proc._reap()
                if name == "controller" and not self.stop_requested:
                    self.notes.append("controller_exited")
            if not proc.pid and now >= proc.next_try and not self.stop_requested:
                if name in ("controller", "dnsmasq") and not self.managed:
                    continue
                try:
                    proc.start()
                    proc.failures = 0
                except OSError as exc:
                    proc.failures += 1
                    proc.next_try = now + min(30.0, 2.0 ** min(proc.failures, 4))
                    self.notes.append(f"start_failed_{name}:{type(exc).__name__}")
            elif proc.pid and not proc.alive():
                proc._reap()

    # -------------------------------------------------------------- readiness
    def vpn_status(self):
        path = self.state_dir / "status.json"
        try:
            status = read_json(path)
        except (OSError, ValueError, SupervisorError):
            return None
        if not isinstance(status, dict) or status.get("schema_version") != STATE_SCHEMA:
            return None
        try:
            age = time.time() - float(status.get("updated_at", 0))
        except (TypeError, ValueError):
            return None
        if age > STATE_MAX_AGE:
            return None
        return status

    def context(self, status) -> dict:
        evidence = status.get("evidence") if isinstance(status.get("evidence"), dict) else {}
        interface = evidence.get("interface") or ""
        try:
            ifindex = socket.if_nametoindex(interface) if interface else 0
        except OSError:
            ifindex = 0
        corp = [item for item in (self.env.get("CORP_CIDRS", "") or "").split(",") if item]
        dns = [item for item in (evidence.get("dns_servers") or []) if isinstance(item, str)]
        return {
            "schema_version": 1, "project": self.env.get("PROJECT_NAME", "feilian"),
            # `ready`/`proxy_enabled` are what the policy modules turn into
            # "proxy_ready". Omitting proxy_enabled silently produced a guard that
            # only contained the uid drop, i.e. every proxy packet was refused.
            "network_mode": self.mode, "ready": False,
            "proxy_enabled": self.env.get("PROXY_ENABLED", "1") == "1",
            "vpn_interface": interface,
            # evidence.vpn_ipv4 is already a bounded list; never nest it again.
            "vpn_ipv4": [item for item in (evidence.get("vpn_ipv4") or [])
                         if isinstance(item, str)],
            "vpn_dns": dns, "source_cidrs": [], "corp_cidrs": corp, "management_cidrs": [],
            "access_interface": self.env.get("ACCESS_INTERFACE", "eth0"),
            "bridge_gateway": self.env.get("BRIDGE_GATEWAY", ""), "macvlan_shim": False,
            "http_port": int(self.env.get("HTTP_PROXY_INTERNAL_PORT", "8118")),
            "socks_port": int(self.env.get("SOCKS_PROXY_INTERNAL_PORT", "1080")),
            "connect_ports": [int(item) for item in self.env.get("PROXY_CONNECT_PORTS", "443").split(",") if item],
            "gateway": {"enabled": self.env.get("GATEWAY_ENABLED", "0") == "1"},
        }

    def _write_context(self, context) -> Path:
        PROXY_DIR.mkdir(mode=0o2750, parents=True, exist_ok=True)
        os.chmod(PROXY_DIR, 0o2750)
        path = PROXY_DIR / "context.json"
        _atomic_json(path, context)
        return path

    def _run_tool(self, argv, timeout=20):
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return 1, ""
        return result.returncode, result.stdout

    def open_data_plane(self, status) -> None:
        context = self.context(status)
        evidence = status.get("evidence") if isinstance(status.get("evidence"), dict) else {}
        # A same-name tunnel rebuild invalidates index-based bindings, so the data
        # plane refuses to open on a name alone.
        ifindex = evidence.get("interface_ifindex")
        if type(ifindex) is not int or ifindex <= 0:
            try:
                ifindex = socket.if_nametoindex(context["vpn_interface"])
            except (OSError, ValueError):
                ifindex = 0
        if not context["vpn_interface"] or ifindex <= 0:
            self.notes.append("data_plane_missing_ifindex")
            return
        context["ready"] = True
        path = self._write_context(context)
        egress = [sys.executable, str(self.runtime_dir / "egress_policy.py")]
        proxy = [sys.executable, str(self.runtime_dir / "proxy_config.py")]
        if self._run_tool(egress + ["apply", "--context", str(path)])[0]:
            self.notes.append("guard_apply_failed")
            return
        code, out = self._run_tool(proxy + ["prepare", "--context", str(path), "--state-dir", str(PROXY_DIR)])
        if code:
            self._run_tool(egress + ["close", "--context", str(path)])
            self.notes.append("proxy_prepare_failed")
            return
        try:
            metadata = json.loads(out)
            spec = json.loads((PROXY_DIR / "proxy" / "microsocks.json").read_text(encoding="utf-8"))
        except (ValueError, OSError):
            self._run_tool(egress + ["close", "--context", str(path)])
            self.notes.append("proxy_config_unreadable")
            return
        if metadata.get("status") != "READY":
            self._run_tool(egress + ["close", "--context", str(path)])
            return
        self.register("microsocks", spec["argv"], user=SOCKS_USER, log="microsocks.log")
        self.register("privoxy", ["privoxy", "--no-daemon",
                                  str(PROXY_DIR / "proxy" / "privoxy.conf")], user=HTTP_USER,
                      log="privoxy.log")
        for name in ("microsocks", "privoxy"):
            try:
                self.procs[name].start()
            except OSError:
                self.notes.append(f"start_failed_{name}")
                self.close_data_plane(force_context=context)
                return
        # Reporting READY before the listeners accept connections makes every
        # consumer see "connection refused" while the status says ready.
        if not self._await_listeners((context["socks_port"], context["http_port"])):
            self.notes.append("proxy_listen_timeout")
            self.close_data_plane(force_context=context)
            return
        self.data_plane = "ready"
        self.data_context = context

    def _await_listeners(self, ports, timeout: float = 15.0) -> bool:
        """Wait until both proxy ports accept a TCP connection."""
        deadline = time.time() + timeout
        pending = set(ports)
        while pending and time.time() < deadline:
            for port in sorted(pending):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                        pending.discard(port)
                except OSError:
                    pass
            if pending:
                time.sleep(0.2)
        return not pending

    def close_data_plane(self, force_context=None) -> None:
        for name in ("microsocks", "privoxy"):
            proc = self.procs.get(name)
            if proc is not None:
                proc.stop(timeout=4.0)
                proc.next_try = float("inf")
        context = getattr(self, "data_context", None) or force_context
        if context:
            path = PROXY_DIR / "context.json"
            if path.exists():
                egress = [sys.executable, str(self.runtime_dir / "egress_policy.py")]
                self._run_tool(egress + ["close", "--context", str(path)])
        self.data_plane = "closed"

    # --------------------------------------------------------------- lifecycle
    def prepare_dirs(self) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
        if not WEB_DIR.exists():
            self.notes.append("web_gateway_missing")

    def state_snapshot(self) -> dict:
        return {
            "schema_version": STATE_SCHEMA,
            "network_mode": self.mode,
            "managed_egress": self.managed,
            "data_plane": self.data_plane,
            "updated_at": time.time(),
            "processes": {name: {"pid": proc.pid, "alive": proc.alive(), "required": proc.required}
                          for name, proc in sorted(self.procs.items())},
            "notes": self.notes[-20:],
            "transitions": getattr(self, "transitions", [])[-10:],
        }

    def publish_state(self) -> None:
        _atomic_json(self.state_dir / "runtime.json", self.state_snapshot())

    def _record(self, ready, status) -> None:
        """Keep a short, bounded transition trace: invaluable when the data plane
        opens and immediately closes without a visible reason in the logs."""
        current = {"ready": bool(ready), "plane": self.data_plane,
                   "state": (status or {}).get("state"),
                   "reason": (status or {}).get("reason")}
        if current == getattr(self, "_last", None):
            return
        self._last = current
        trace = getattr(self, "transitions", None)
        if trace is None:
            trace = self.transitions = []
        trace.append(dict(current, t=round(time.time())))
        del trace[:-10]

    def tick(self) -> None:
        self.sync_processes()
        if self.managed and not self.draining:
            status = self.vpn_status()
            ready = bool(status) and status.get("state") == "READY" and status.get("ready") is True
            self._record(ready, status)
            if ready and self.data_plane != "ready":
                self.open_data_plane(status)
            elif not ready and self.data_plane == "ready":
                self.notes.append("readiness_lost")
                self.close_data_plane()
        self.publish_state()

    def request_stop(self, *_):
        self.stop_requested = True

    def drain(self) -> None:
        self.draining = True
        self.publish_state()
        self.close_data_plane()
        controller = self.procs.get("controller")
        if controller is not None:
            controller.stop(timeout=12.0)
        for name in ("dnsmasq", "gui", "service", "nginx", "websockify", "x11vnc", "xvfb"):
            proc = self.procs.get(name)
            if proc is not None:
                proc.stop(timeout=6.0)
        if self.managed:
            path = PROXY_DIR / "context.json"
            if path.exists():
                self._run_tool([sys.executable, str(self.runtime_dir / "egress_policy.py"),
                                "cleanup", "--context", str(path)])
        self.data_plane = "closed"
        self.publish_state()

    def run(self, duration: float | None = None) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self.request_stop)
        self.prepare_dirs()
        self._bootstrap_plan()
        started = time.time()
        try:
            while not self.stop_requested:
                self.tick()
                if duration is not None and time.time() - started >= duration:
                    break
                time.sleep(1.0)
        finally:
            self.drain()
        return 0


def health(state_dir=STATE_DIR) -> int:
    path = Path(state_dir) / "runtime.json"
    try:
        state = read_json(path)
        age = time.time() - float(state["updated_at"])
    except (OSError, ValueError, KeyError, TypeError, SupervisorError):
        return 1
    if age > 45:
        return 1
    processes = state.get("processes") or {}
    for name in CRITICAL:
        entry = processes.get(name)
        if entry is not None and not entry.get("alive"):
            return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "health", "status"))
    parser.add_argument("--state-dir", default=str(STATE_DIR))
    parser.add_argument("--duration", type=float, default=None)
    args = parser.parse_args(argv)
    if args.command == "health":
        return health(args.state_dir)
    if args.command == "status":
        try:
            print(json.dumps(read_json(Path(args.state_dir) / "runtime.json"), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, SupervisorError):
            return 1
    try:
        return Supervisor(state_dir=Path(args.state_dir)).run(args.duration)
    except SupervisorError as exc:
        print(f"feilian supervisor: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
