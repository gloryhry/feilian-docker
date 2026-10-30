#!/usr/bin/env python3
"""Strict verification driver. No suite silently substitutes mocks for official.

Only `unit` and `compose` are offline. `mock`/`client` explicitly create isolated
Docker resources; `release` verifies a registry and never publishes. Report files
and optional screenshots stay below .state; raw inspect/env/logs are never printed.
Required FAIL, SKIP, WAITING_AUTH or NOT_IMPLEMENTED checks cause nonzero exit.
A client smoke may exit zero with a non-required WAITING_AUTH row: that means
runtime/GUI smoke passed, NOT that the enterprise VPN or release acceptance passed.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"PASS", "FAIL", "WAITING_AUTH", "SKIP"}
NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}\Z")
IMAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,254}\Z")
OWNER_LABEL = "io.feilian.test.owner"
CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
        "NET_BIND_SERVICE", "NET_RAW", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE", "SETFCAP", "NET_ADMIN"}


class VerificationError(Exception):
    pass


class Runner:
    def run(self, args, timeout=60, env=None, input_data=None):
        return subprocess.run(args, cwd=ROOT, env=env, input=input_data, capture_output=True,
                              timeout=timeout, check=False)


class Report:
    def __init__(self, suite, run_id, path=None):
        self.suite, self.run_id, self.path = suite, run_id, path
        self.checks = []

    def add(self, name, status, detail, required=True, evidence=None):
        if status not in STATUSES or not re.fullmatch(r"[a-z0-9_.-]+", name):
            raise ValueError("invalid verification result")
        result = {"name": name, "status": status, "required": bool(required),
                  "detail": detail, "evidence": evidence or {}}
        self.checks.append(result)
        print(json.dumps(result, sort_keys=True))
        return status == "PASS"

    @property
    def failed(self):
        return not self.checks or any(check["required"] and check["status"] != "PASS" for check in self.checks)

    def document(self):
        status = "FAIL" if self.failed else next((item for item in ("WAITING_AUTH", "SKIP")
                    if any(check["status"] == item for check in self.checks)), "PASS")
        return {"schema_version": 1, "suite": self.suite, "run_id": self.run_id,
                "status": status, "checks": self.checks,
                "scope": "This report proves only named checks, not untested host or enterprise isolation."}

    def finish(self):
        if self.path is not None:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise VerificationError("unsafe_report_path")
            with tempfile.NamedTemporaryFile("w", dir=self.path.parent, prefix=".report-", delete=False) as stream:
                temporary = Path(stream.name)
                os.chmod(temporary, 0o600)
                json.dump(self.document(), stream, indent=2, sort_keys=True)
                stream.write("\n")
            os.replace(temporary, self.path)
        return int(self.failed)


def private_path(value, root=ROOT):
    path = Path(value)
    path = path if path.is_absolute() else root / path
    path = path.absolute()
    state = root / ".state"
    if ".." in path.parts or path == state or state not in path.parents:
        raise VerificationError("evidence_must_stay_under_state")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise VerificationError("unsafe_evidence_path")
    return path


def valid_image(value):
    if not value or not IMAGE.fullmatch(value) or value.startswith("-"):
        raise VerificationError("invalid_image_reference")
    return value


def image_kind(inspect, expected):
    labels = inspect.get("Config", {}).get("Labels", {}) or {}
    if labels.get("io.feilian.client.kind") != expected:
        raise VerificationError("image_kind_mismatch")
    return labels


def isolation_errors(info):
    """Inspect only metadata, never /etc/shadow, credential files or hashes."""
    errors = []
    host = info.get("HostConfig", {})
    if host.get("Privileged") is not False:
        errors.append("privileged")
    if host.get("PidMode") or host.get("IpcMode") == "host":
        errors.append("shared_pid_or_host_ipc")
    if host.get("NetworkMode") == "host":
        errors.append("host_network")
    added = {str(cap).removeprefix("CAP_") for cap in host.get("CapAdd", []) or []}
    dropped = {str(cap).removeprefix("CAP_") for cap in host.get("CapDrop", []) or []}
    if not added <= CAPS or "ALL" not in dropped:
        errors.append("capability_contract")
    if not any(item in ("no-new-privileges", "no-new-privileges:true") for item in host.get("SecurityOpt", []) or []):
        errors.append("no_new_privileges_missing")
    for device in host.get("Devices", []) or []:
        if device.get("PathOnHost") != "/dev/net/tun" or device.get("PathInContainer") != "/dev/net/tun":
            errors.append("unexpected_device")
    allowed_volumes = {"/home/feilian", "/root", "/var/log/feilian", "/run/feilian-secrets"}
    for mount in info.get("Mounts", []):
        kind, target = mount.get("Type"), mount.get("Destination")
        if kind == "volume" and target in allowed_volumes:
            continue
        if kind == "tmpfs" and target in ("/run", "/tmp", "/run/feilian", "/run/feilian-web"):
            continue
        if kind == "bind" and target in ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf"):
            continue
        errors.append("unexpected_mount")
    if host.get("Binds"):
        errors.append("explicit_bind_mount")
    return sorted(set(errors))


def actual_display(info):
    env = {}
    for entry in info.get("Config", {}).get("Env", []) or []:
        key, _, value = entry.partition("=")
        if key in ("DISPLAY", "DISPLAY_NUM", "GUI_MODE", "X11_DISPLAY"):
            env[key] = value
    display = env.get("X11_DISPLAY") if env.get("GUI_MODE") == "x11" else env.get("DISPLAY") or ":" + env.get("DISPLAY_NUM", "99")
    if not display or not re.fullmatch(r":[0-9]{1,3}(?:\.[0-9])?", display):
        raise VerificationError("invalid_or_unavailable_display")
    return display


class Driver:
    def __init__(self, report, runner=None, root=ROOT, docker_host=None):
        self.report, self.runner, self.root = report, runner or Runner(), Path(root)
        self.docker_host = docker_host or os.environ.get("DOCKER_HOST") or "unix:///var/run/docker.sock"
        if not self.docker_host.startswith("unix:///") or any(c in self.docker_host for c in ("\n", "\r", "\0")):
            raise VerificationError("only_local_unix_docker_endpoint_allowed")

    def call(self, args, timeout=60, env=None, input_data=None, check=True):
        try:
            result = self.runner.run(args, timeout=timeout, env=env, input_data=input_data)
        except (OSError, subprocess.TimeoutExpired):
            raise VerificationError("command_unavailable_or_timeout") from None
        if check and result.returncode:
            raise VerificationError("command_failed")
        return result

    def docker(self, *args, **kwargs):
        return self.call(["docker", "--host", self.docker_host, *args], **kwargs)

    def inspect(self, name, kind="container"):
        result = self.docker(kind, "inspect", name)
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
                raise ValueError()
            return data[0]
        except (ValueError, TypeError):
            raise VerificationError("invalid_docker_metadata") from None

    def unit(self):
        result = self.call([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/unit", "-v"], timeout=240, check=False)
        self.report.add("unit", "PASS" if result.returncode == 0 else "FAIL", "offline_unittest_exit",
                        evidence={"exit_code": result.returncode})
        paths = sorted(set(self.root.glob("*.sh")) | set((self.root / "scripts").rglob("*.sh")) | set((self.root / "verify").glob("*.sh")))
        for path in paths:
            result = self.call(["bash", "-n", str(path)], check=False)
            self.report.add("syntax." + path.name.replace("_", "-"), "PASS" if result.returncode == 0 else "FAIL", "bash_syntax")

    def compose(self):
        # Rendering does not require or contact a daemon. Empty env-file and
        # explicit dummy settings prevent accidental dotenv/credential loading.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent",
               "PROJECT_NAME": "verification-contract", "IMAGE_REF": "example.invalid/feilian:contract",
               "WEB_BIND": "127.0.0.1", "WEB_AUTH": "1", "WEB_TLS": "selfsigned",
               "WEB_SOURCE_CIDRS": "192.0.2.0/24", "MACVLAN_IP": "192.0.2.9"}
        for filename in ("compose.yaml", "compose.host.yaml", "compose.macvlan.yaml"):
            try:
                result = self.call(["docker", "compose", "--env-file", "/dev/null", "-f", str(self.root / filename), "config", "--format", "json"], env=env)
                data = json.loads(result.stdout)
                service = data["services"]["feilian"]
                safe = (not service.get("privileged") and service.get("pid") != "host"
                        and "SYS_ADMIN" not in service.get("cap_add", [])
                        and "ALL" in service.get("cap_drop", [])
                        and all(mount["type"] == "volume" for mount in service.get("volumes", [])))
                if filename == "compose.host.yaml":
                    safe = safe and service.get("network_mode") == "host" and not service.get("ports")
                    safe = safe and all(str(service["environment"].get(key)) == "0" for key in ("PROXY_ENABLED", "GUARD_ENABLED", "GATEWAY_ENABLED"))
                    safe = safe and service["environment"].get("DNS_MODE") == "off"
                else:
                    safe = safe and service.get("network_mode") != "host"
                self.report.add(filename.replace(".yaml", ""), "PASS" if safe else "FAIL", "rendered_compose_contract")
            except (VerificationError, ValueError, KeyError, TypeError):
                self.report.add(filename.replace(".yaml", ""), "FAIL", "compose_render_or_contract_failed")

    def isolation(self, name):
        errors = isolation_errors(self.inspect(name))
        self.report.add("isolation.metadata", "FAIL" if errors else "PASS", "mount_pid_caps_device_contract",
                        evidence={"violations": errors})
        return not errors

    def status(self, name):
        result = self.docker("exec", name, "python3", "/opt/feilian/runtime/vpn_state.py", "status")
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, dict) or data.get("schema_version") != 1 or type(data.get("ready")) is not bool or type(data.get("live")) is not bool:
                raise ValueError()
            return data
        except (ValueError, TypeError):
            raise VerificationError("invalid_runtime_status") from None

    def network(self, name, doctor=False):
        if doctor:
            # Diagnostic exit never claims readiness and performs no public pings.
            info = self.inspect(name)
            self.report.add("network.doctor", "SKIP", "diagnostics_are_not_acceptance", required=False,
                            evidence={"running": info.get("State", {}).get("Running") is True})
            return
        snapshot = self.status(name)
        if snapshot["ready"] and snapshot["state"] == "READY":
            self.report.add("network.ready", "PASS", "fresh_controller_joint_probe_ready")
        else:
            state = snapshot.get("state")
            status = "WAITING_AUTH" if state in ("UNCONFIGURED", "WAITING_AUTH") else "FAIL"
            self.report.add("network.ready", status, "enterprise_vpn_not_ready")

    def window(self, name, capture=None):
        display = actual_display(self.inspect(name))
        result = self.docker("exec", "--env", "DISPLAY=" + display, name, "xwininfo", "-root", "-tree")
        # Do not print titles/window trees: they may contain account information.
        tree = result.stdout.decode("utf-8", "replace")
        count = len(re.findall(r"^\s+0x[0-9a-f]+\s", tree, re.MULTILINE))
        self.report.add("gui.window", "PASS" if count > 0 else "FAIL", "x_window_count",
                        evidence={"display": display, "window_count": count})
        if capture is not None:
            capture = private_path(capture, self.root)
            capture.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            remote = "/tmp/feilian-verification-window.png"
            self.docker("exec", "--env", "DISPLAY=" + display, name, "scrot", "-o", remote)
            self.docker("cp", name + ":" + remote, str(capture))
            os.chmod(capture, 0o600)
            self.report.add("gui.capture", "PASS", "private_opt_in_capture_not_isolation_proof", required=False)

    def smoke_existing(self, name, image):
        metadata = self.inspect(image, "image")
        labels = image_kind(metadata, "official")
        lock = json.loads((self.root / "config/client.lock.json").read_text())
        expected = lock["release"]
        matches = labels.get("io.feilian.client.version") == expected["version"] and labels.get("io.feilian.client.revision") == expected["revision"]
        self.report.add("client.official", "PASS" if matches else "FAIL", "official_label_and_locked_release")
        native = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "amd64": "amd64"}.get(platform.machine().lower())
        arch = metadata.get("Architecture")
        self.report.add("client.native_arch", "PASS" if arch == native else "FAIL", "no_emulated_release_smoke",
                        evidence={"image_arch": arch, "runner_arch": native})
        self.isolation(name)
        snapshot = self.status(name)
        self.report.add("client.controller_live", "PASS" if snapshot["live"] and not snapshot["ready"] else "FAIL", "no_account_no_fake_readiness")
        if snapshot.get("state") in ("UNCONFIGURED", "WAITING_AUTH") and not snapshot["ready"]:
            self.report.add("client.enterprise_auth", "WAITING_AUTH", "manual_enterprise_login_not_performed", required=False)
        else:
            self.report.add("client.enterprise_auth", "FAIL", "unexpected_no_account_state")
        processes = self.docker("top", name, "-eo", "uid,comm").stdout.decode("utf-8", "replace")
        rows = [line.split() for line in processes.splitlines()[1:]]
        nonroot_gui = any(len(row) == 2 and row[0] not in ("0", "root") and row[1].startswith("corplink") for row in rows)
        self.report.add("client.nonroot_gui", "PASS" if nonroot_gui else "FAIL", "gui_uid_contract")
        self.window(name)

    def load_integration(self, filename):
        path = self.root / "tests/integration" / filename
        spec = importlib.util.spec_from_file_location("feilian_verification_" + path.stem, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("all", "isolation", "network", "window", "client"))
    parser.add_argument("--suite", choices=("unit", "compose", "mock", "client", "release"))
    parser.add_argument("--image")
    parser.add_argument("--container", default=os.environ.get("NAME", "feilian"))
    parser.add_argument("--run-id", default="verify-" + str(int(time.time())) + "-" + str(os.getpid()))
    parser.add_argument("--report")
    parser.add_argument("--capture")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--keep-on-failure", action="store_true")
    args = parser.parse_args(argv)
    if not NAME.fullmatch(args.run_id) or not NAME.fullmatch(args.container):
        parser.error("run-id and container must be literal Docker names")
    suite = args.suite or args.command
    if args.command == "all" and args.suite is None:
        parser.error("--suite is required; no implicit real network operations")
    try:
        report_path = private_path(args.report or f".state/verification/{args.run_id}/report.json")
        report = Report(suite, args.run_id, report_path)
        driver = Driver(report)
        if args.command == "isolation":
            driver.isolation(args.container)
        elif args.command == "network":
            driver.network(args.container, args.doctor)
        elif args.command == "window":
            driver.window(args.container, args.capture)
        elif args.command == "client":
            driver.smoke_existing(args.container, valid_image(args.image))
        elif suite == "unit":
            driver.unit()
        elif suite == "compose":
            driver.compose()
        elif suite in ("mock", "client"):
            driver.load_integration("lab.py").run(driver, suite, args)
        elif suite == "release":
            driver.load_integration("release_check.py").verify_release(driver, valid_image(args.image))
    except (VerificationError, OSError, ValueError, KeyError, TypeError) as exc:
        if "report" not in locals():
            print(json.dumps({"status": "FAIL", "detail": "invalid_verification_request"}))
            return 2
        code = str(exc) if re.fullmatch(r"[a-z0-9_]+", str(exc)) else "verification_operation_failed"
        report.add("driver", "FAIL", code)
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
