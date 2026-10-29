#!/usr/bin/env python3
"""Manage project-owned secret volumes without putting credentials in logs.

ensure is idempotent. import/rotate are explicit operations. Local credential
backups are copied from the helper using docker cp, never stdout. Imported
*_FILE values are authorized host sources. Their bounded contents are transferred
as base64 in a strict stdin JSON envelope, never Docker argv/env/bind mounts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

import config

ROOT = Path(__file__).resolve().parent.parent
SOURCE_KEYS = {
    "WEB_AUTH_FILE": ("web_auth_file", "web.htpasswd", True),
    "VNC_PASSWORD_FILE": ("vnc_password_file", "vnc-password", True),
    "WEB_TLS_CERT_FILE": ("tls_cert_file", "tls.crt", False),
    "WEB_TLS_KEY_FILE": ("tls_key_file", "tls.key", True),
    "VPN_PROBE_CA_FILE": ("probe_ca_file", "probe-ca.crt", False),
}


class SecretsError(ValueError):
    pass


class Runner:
    def call(self, args, check=True, input_data=None):
        try:
            input_options = {"input": input_data} if input_data is not None else {"stdin": subprocess.DEVNULL}
            result = subprocess.run(args, capture_output=True, text=True, timeout=90, **input_options)
        except (OSError, subprocess.TimeoutExpired):
            raise SecretsError("Docker command unavailable or timed out") from None
        if check and result.returncode:
            # Docker/helper output may contain secret material: never forward it.
            raise SecretsError("Docker secrets operation failed")
        return result


def _path(value):
    path = Path(value).absolute()
    if path.resolve() != path or any(ord(char) < 32 for char in str(path)):
        raise SecretsError("secret/state paths must not traverse symlinks")
    return path


def _source(value, root, private):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    path = _path(path)
    try:
        details = path.lstat()
    except OSError:
        raise SecretsError("secret import source does not exist") from None
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 65536:
        raise SecretsError("secret import source must be a bounded regular file")
    if private and stat.S_IMODE(details.st_mode) & 0o077:
        raise SecretsError("private secret import sources require mode 0600 or stricter")
    return path


def encode_sources(sources):
    encoded = {}
    for kind, (path, _) in sources.items():
        private = kind in {"credential_file", "web_auth_file", "vnc_password_file", "tls_key_file"}
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as handle:
                details = os.fstat(handle.fileno())
                if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                        or (private and stat.S_IMODE(details.st_mode) & 0o077)):
                    raise SecretsError("secret source changed or has unsafe permissions")
                content = handle.read(65537)
        except OSError:
            raise SecretsError("cannot read authorized secret import source") from None
        if len(content) > 65536:
            raise SecretsError("secret source exceeds size limit")
        encoded[kind] = base64.b64encode(content).decode("ascii")
    payload = json.dumps({"schema_version": 1, "imports": encoded}, separators=(",", ":"))
    if len(payload) > 600000:
        raise SecretsError("secret envelope exceeds size limit")
    return payload


def _json(result):
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError):
        raise SecretsError("unexpected Docker metadata") from None


class Manager:
    def __init__(self, settings, root=ROOT, runner=None):
        self.settings = settings
        self.root = _path(root)
        self.project = settings["PROJECT_NAME"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", self.project):
            raise SecretsError("invalid secrets project")
        self.owner = hashlib.sha256((str(self.root) + ":" + self.project).encode()).hexdigest()[:12]
        self.volume = self.project + "-secrets"
        self.runner = Runner() if runner is None else runner
        self.backup = self.root / ".state" / self.project / "access.json"

    def sources(self, credential_file=None):
        sources = {}
        for key, (kind, target, private) in SOURCE_KEYS.items():
            if self.settings.get(key):
                sources[kind] = (_source(self.settings[key], self.root, private), target)
        if credential_file:
            sources["credential_file"] = (_source(credential_file, self.root, True), "credentials.json")
        return sources

    def helper_command(self, action, name, sources):
        command = ["docker", "create", "--interactive", "--name", name, "--network", "none", "--cap-drop", "ALL",
                   "--cap-add", "CHOWN",
                   "--security-opt", "no-new-privileges:true", "--read-only",
                   "--label", "io.feilian.owner=" + self.owner,
                   "--label", "io.feilian.project=" + self.project,
                   "--label", "io.feilian.role=secrets-helper",
                   "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                   "--mount", "type=volume,src=" + self.volume + ",dst=/secrets"]
        command += ["--entrypoint", "python3", self.settings["IMAGE_REF"],
                    "/opt/feilian/runtime/secrets_volume.py", action, "--secrets-dir", "/secrets",
                    "--project", self.project, "--owner", self.owner, "--stdin-json"]
        return command

    def _owned_volume(self, data):
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise SecretsError("invalid secrets volume metadata")
        volume = data[0]
        labels = volume.get("Labels") or {}
        if (volume.get("Name") != self.volume or volume.get("Driver") != "local"
                or labels.get("io.feilian.owner") != self.owner
                or labels.get("io.feilian.project") != self.project
                or labels.get("io.feilian.role") != "secrets"):
            raise SecretsError("refusing foreign secrets volume")

    def ensure_volume(self):
        result = self.runner.call(["docker", "volume", "inspect", self.volume], check=False)
        if not result.returncode:
            self._owned_volume(_json(result))
            return
        listing = self.runner.call(["docker", "volume", "ls", "--format", "{{.Name}}"])
        if self.volume in listing.stdout.splitlines():
            raise SecretsError("cannot inspect existing secrets volume")
        self.runner.call(["docker", "volume", "create", "--driver", "local",
                          "--label", "io.feilian.owner=" + self.owner,
                          "--label", "io.feilian.project=" + self.project,
                          "--label", "io.feilian.role=secrets", self.volume])
        self._owned_volume(_json(self.runner.call(["docker", "volume", "inspect", self.volume])))

    def _export_backup(self, container):
        parent = _path(self.backup.parent)
        self.backup = _path(self.backup)
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        temporary = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".access-", suffix=".json", dir=parent)
            os.close(descriptor)
            temporary = Path(name)
            os.chmod(temporary, 0o600)
            self.runner.call(["docker", "cp", container + ":/secrets/access.json", str(temporary)])
            details = temporary.lstat()
            if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                    or details.st_size == 0 or details.st_size > 65536):
                raise SecretsError("invalid credential backup copy")
            os.chmod(temporary, 0o600)
            if _path(self.backup) != self.backup or _path(parent) != parent:
                raise SecretsError("credential backup target changed")
            os.replace(temporary, self.backup)
            temporary = None
        finally:
            if temporary is not None and temporary.resolve().parent == parent:
                temporary.unlink(missing_ok=True)

    def _remove_helper(self, container):
        result = self.runner.call(["docker", "container", "inspect", "--format", "{{json .Config.Labels}}", container])
        labels = _json(result)
        if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in {
                "io.feilian.owner": self.owner, "io.feilian.project": self.project,
                "io.feilian.role": "secrets-helper"}.items()):
            raise SecretsError("refusing foreign helper cleanup")
        self.runner.call(["docker", "rm", container])

    def perform(self, action, credential_file=None, dry_run=False):
        if action not in {"ensure", "import", "rotate"}:
            raise SecretsError("unknown secrets action")
        sources = self.sources(credential_file)
        if action == "import" and not sources:
            raise SecretsError("import requires --from or configured secret-file sources")
        name = self.project + "-secrets-helper-" + secrets.token_hex(6)
        command = self.helper_command(action, name, sources)
        if dry_run:
            return {"project": self.project, "volume": self.volume, "backup": str(self.backup), "helper_command": command}
        payload = encode_sources(sources)
        self.ensure_volume()
        created = self.runner.call(command).stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{12,64}", created):
            raise SecretsError("unexpected helper container identity")
        try:
            self.runner.call(["docker", "start", "--attach", "--interactive", created], input_data=payload)
            # docker start --attach propagates helper exit; inspect again to be
            # conservative across Docker versions and daemon adapters.
            result = self.runner.call(["docker", "inspect", "--format", "{{.State.ExitCode}}", created])
            if result.stdout.strip() != "0":
                raise SecretsError("secret helper failed; use explicit import/rotate for changed sources")
            self._export_backup(created)
        finally:
            self._remove_helper(created)
        return {"project": self.project, "volume": self.volume, "backup": str(self.backup)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ensure", "rotate", "import"))
    parser.add_argument("--config")
    parser.add_argument("--set", dest="overrides", action="append", default=[])
    parser.add_argument("--from", dest="credential_file")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.credential_file and args.command != "import":
        parser.error("--from is only valid for explicit import")
    try:
        settings = config.load_config(args.config, overrides=args.overrides)
        result = Manager(settings).perform(args.command, args.credential_file, args.dry_run)
    except (config.ConfigError, SecretsError, OSError):
        print("feilian secrets: operation failed; check ownership/import permissions; changed sources require explicit import or rotate", file=sys.stderr)
        return 2
    if args.dry_run:
        print(json.dumps(result, indent=2))
    else:
        print("feilian secrets: ready; private credential backup: " + result["backup"])
        if args.command != "ensure":
            print("feilian secrets: restart the application to load explicitly changed secrets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
