#!/usr/bin/env python3
"""Offline helper for an owned Docker secrets volume. Never print credentials.

Run only in a network-none helper with the named volume mounted at /secrets.
ensure is idempotent; import/rotate are explicit changes. Child command output
is always captured, including x11vnc prompts and openssl diagnostics. Passwords
are provided on stdin, never process arguments, environment variables or logs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
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


class SecretsError(ValueError):
    pass


FILES = {"web.htpasswd": 0o640, "vnc.pass": 0o600, "tls.crt": 0o644,
         "tls.key": 0o600, "access.json": 0o600, ".owner.json": 0o600}
IMPORT_KEYS = ("web_auth_file", "vnc_password_file", "tls_cert_file", "tls_key_file", "probe_ca_file", "credential_file")
USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")


class Runner:
    def call(self, args, input_data=None):
        try:
            input_options = {"input": input_data} if input_data is not None else {"stdin": subprocess.DEVNULL}
            result = subprocess.run(args, capture_output=True, timeout=40,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/tmp"},
                                    **input_options)
        except (OSError, subprocess.TimeoutExpired):
            raise SecretsError("secret helper command unavailable or timed out") from None
        if result.returncode:
            raise SecretsError("secret helper command failed")
        return result.stdout


def _path(value):
    path = Path(value).absolute()
    if path.resolve() != path or any(ord(c) < 32 for c in str(path)):
        raise SecretsError("secret paths must not traverse symlinks")
    return path


def _read(path, limit=65536):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            details = os.fstat(handle.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise SecretsError("secret input must be a regular unlinked file")
            raw = handle.read(limit + 1)
    except OSError:
        raise SecretsError("secret input is not readable") from None
    if len(raw) > limit:
        raise SecretsError("secret input exceeds size limit")
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SecretsError("duplicate secret JSON field")
        result[key] = value
    return result


def _json(raw):
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError):
        raise SecretsError("invalid secret JSON") from None
    if not isinstance(data, dict):
        raise SecretsError("secret JSON must be an object")
    return data


def _password(value, vnc=False):
    if (not isinstance(value, str) or not (1 if vnc else 12) <= len(value) <= (8 if vnc else 256)
            or any(not 33 <= ord(c) <= 126 for c in value)):
        raise SecretsError("invalid password length or encoding")
    return value


def _write(path, content):
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _check_files(directory, check_owner):
    for name, mode in FILES.items():
        try:
            details = (directory / name).lstat()
        except OSError:
            raise SecretsError("incomplete secrets volume; explicitly import or rotate") from None
        if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != mode):
            raise SecretsError("invalid secret file type or permissions")
        if check_owner and (details.st_uid != 0 or details.st_gid != (33 if name == "web.htpasswd" else 0)):
            raise SecretsError("invalid secret file ownership")
    if (directory / "probe-ca.crt").exists() or (directory / "probe-ca.crt").is_symlink():
        details = (directory / "probe-ca.crt").lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o644:
            raise SecretsError("invalid probe CA file")


def _manage_locked(action, secrets_dir, project, owner, imports=None, runner=None, check_owner=True, import_data=None):
    if action not in {"ensure", "rotate", "import"} or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
        raise SecretsError("invalid secret operation or project")
    if not re.fullmatch(r"[a-f0-9]{12}", owner):
        raise SecretsError("invalid secrets owner")
    directory = _path(secrets_dir)
    supplied = {key: _path(value) for key, value in (imports or {}).items() if value}
    if any(key not in IMPORT_KEYS for key in supplied):
        raise SecretsError("unknown secret import kind")
    if bool(supplied.get("tls_cert_file")) != bool(supplied.get("tls_key_file")):
        raise SecretsError("TLS certificate and key must be imported together")
    if import_data is not None and supplied:
        raise SecretsError("cannot mix stdin and file import sources")
    contents = dict(import_data) if import_data is not None else {key: _read(path) for key, path in supplied.items()}
    if (any(key not in IMPORT_KEYS or not isinstance(raw, bytes) or len(raw) > 65536 for key, raw in contents.items())
            or bool(contents.get("tls_cert_file")) != bool(contents.get("tls_key_file"))):
        raise SecretsError("invalid bounded import contents or incomplete TLS pair")
    fingerprints = {key: hashlib.sha256(raw).hexdigest() for key, raw in contents.items()}
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    existing = (directory / ".owner.json").exists() or (directory / ".owner.json").is_symlink()
    previous = {}
    if existing:
        details = directory.stat()
        if (stat.S_IMODE(details.st_mode) != 0o750
                or (check_owner and (details.st_uid != 0 or details.st_gid != 33))):
            raise SecretsError("invalid secrets directory ownership or permissions")
        previous = _json(_read(directory / ".owner.json"))
        if previous.get("schema_version") != 1 or previous.get("project") != project or previous.get("owner") != owner:
            raise SecretsError("secrets volume ownership mismatch")
        _check_files(directory, check_owner)
        if action == "ensure":
            if any(previous.get("imports", {}).get(key) != digest for key, digest in fingerprints.items()):
                raise SecretsError("new secret import source requires explicit import or rotate")
            return {"project": project, "changed": False}
    elif any(directory.iterdir()):
        raise SecretsError("refusing nonempty unowned secrets directory")
    if action == "import" and not contents:
        raise SecretsError("import requires an explicit source")
    credentials = _json(contents["credential_file"]) if "credential_file" in contents else {}
    if (set(credentials) - {"username", "web_password", "vnc_password"}
            or bool("username" in credentials) != bool("web_password" in credentials)):
        raise SecretsError("invalid credential import fields")
    if "web_auth_file" in contents and "web_password" in credentials:
        raise SecretsError("conflicting web credential sources")
    if "vnc_password_file" in contents and "vnc_password" in credentials:
        raise SecretsError("conflicting VNC credential sources")
    keep = existing and action == "import"
    backup = _json(_read(directory / "access.json")) if keep else {}
    username, web_password, vnc_password = backup.get("username", "feilian"), backup.get("web_password"), backup.get("vnc_password")
    tool = Runner() if runner is None else runner
    os.chmod(directory, 0o750)
    if check_owner:
        os.chown(directory, 0, 33)
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=directory) as name:
        stage = Path(name)
        if "web_auth_file" in contents:
            auth = contents["web_auth_file"].rstrip(b"\r\n")
            if not re.fullmatch(rb"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}", auth):
                raise SecretsError("WEB_AUTH_FILE must contain exactly one bcrypt htpasswd entry")
            username, web_password = auth.split(b":", 1)[0].decode("ascii"), None
            _write(stage / "web.htpasswd", auth + b"\n")
        elif "web_password" in credentials or not keep:
            username = credentials.get("username", "feilian")
            if not isinstance(username, str) or not USER.fullmatch(username):
                raise SecretsError("invalid web username")
            web_password = _password(credentials.get("web_password", secrets.token_urlsafe(24)))
            auth = tool.call(["htpasswd", "-niB", "-C", "12", username], (web_password + "\n").encode())
            if not auth.startswith((username + ":$2").encode()) or b"\n" in auth.rstrip(b"\n"):
                raise SecretsError("bcrypt credential generation failed")
            _write(stage / "web.htpasswd", auth)
        else:
            _write(stage / "web.htpasswd", _read(directory / "web.htpasswd"))
        if "vnc_password_file" in contents:
            try:
                vnc_password = _password(contents["vnc_password_file"].rstrip(b"\r\n").decode("ascii"), vnc=True)
            except UnicodeError:
                raise SecretsError("VNC password must be printable ASCII") from None
        elif "vnc_password" in credentials or not keep:
            vnc_password = _password(credentials.get("vnc_password", secrets.token_urlsafe(6)), vnc=True)
        if "vnc_password_file" in contents or "vnc_password" in credentials or not keep:
            tool.call(["x11vnc", "-storepasswd", str(stage / "vnc.pass")], (vnc_password + "\n" + vnc_password + "\ny\n").encode())
            if len(_read(stage / "vnc.pass", 8)) != 8:
                raise SecretsError("VNC authentication generation failed")
        else:
            _write(stage / "vnc.pass", _read(directory / "vnc.pass", 8))
        if "tls_cert_file" in contents:
            _write(stage / "tls.crt", contents["tls_cert_file"])
            _write(stage / "tls.key", contents["tls_key_file"])
            tool.call(["openssl", "x509", "-in", str(stage / "tls.crt"), "-noout"])
            tool.call(["openssl", "pkey", "-in", str(stage / "tls.key"), "-noout"])
            cert_public = tool.call(["openssl", "x509", "-in", str(stage / "tls.crt"), "-pubkey", "-noout"])
            key_public = tool.call(["openssl", "pkey", "-in", str(stage / "tls.key"), "-pubout"])
            if not cert_public.strip() or cert_public.strip() != key_public.strip():
                raise SecretsError("imported TLS certificate and key do not match")
        elif keep:
            for filename in ("tls.crt", "tls.key"):
                _write(stage / filename, _read(directory / filename))
        else:
            tool.call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "365",
                       "-subj", "/CN=" + project + ".local", "-addext", "subjectAltName=DNS:" + project + ".local,DNS:localhost,IP:127.0.0.1,IP:::1",
                       "-keyout", str(stage / "tls.key"), "-out", str(stage / "tls.crt")])
        if "probe_ca_file" in contents:
            _write(stage / "probe-ca.crt", contents["probe_ca_file"])
            tool.call(["openssl", "x509", "-in", str(stage / "probe-ca.crt"), "-noout"])
        elif existing and (directory / "probe-ca.crt").exists():
            _write(stage / "probe-ca.crt", _read(directory / "probe-ca.crt"))
        saved = {"schema_version": 1, "project": project, "username": username,
                 "web_password": web_password, "vnc_password": vnc_password}
        _write(stage / "access.json", (json.dumps(saved, indent=2) + "\n").encode())
        source_hashes = dict(previous.get("imports", {})) if keep else {}
        if existing and "probe_ca_file" not in fingerprints and "probe_ca_file" in previous.get("imports", {}):
            source_hashes["probe_ca_file"] = previous["imports"]["probe_ca_file"]
        source_hashes.update(fingerprints)
        marker = {"schema_version": 1, "project": project, "owner": owner, "imports": source_hashes}
        _write(stage / ".owner.json", (json.dumps(marker, sort_keys=True) + "\n").encode())
        names = list(FILES) + (["probe-ca.crt"] if (stage / "probe-ca.crt").exists() else [])
        for filename in names:
            path = stage / filename
            # Never install tool output unless it is a bounded regular file.
            _read(path)
            os.chmod(path, FILES.get(filename, 0o644))
            if check_owner:
                os.chown(path, 0, 33 if filename == "web.htpasswd" else 0)
        if _path(directory) != directory:
            raise SecretsError("secrets directory changed during preparation")
        for filename in names:
            target = directory / filename
            if target.is_symlink() or (target.exists() and target.stat().st_nlink != 1):
                raise SecretsError("secret target changed during preparation")
        for filename in names:
            os.replace(stage / filename, directory / filename)
    return {"project": project, "changed": True}


def manage(action, secrets_dir, project, owner, imports=None, runner=None, check_owner=True, import_data=None):
    directory = _path(secrets_dir)
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise SecretsError("cannot lock secrets directory") from None
    try:
        try:
            # Directory inode locks are shared across helpers mounting this volume;
            # no lock file or plaintext material is left outside the volume.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SecretsError("another secrets operation is in progress") from None
        return _manage_locked(action, directory, project, owner, imports, runner, check_owner, import_data)
    finally:
        os.close(descriptor)


def decode_stdin(raw):
    if not isinstance(raw, bytes) or len(raw) > 600000:
        raise SecretsError("stdin import envelope exceeds size limit")
    data = _json(raw)
    if set(data) != {"schema_version", "imports"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise SecretsError("invalid stdin import schema")
    encoded = data["imports"]
    if not isinstance(encoded, dict) or set(encoded) - set(IMPORT_KEYS):
        raise SecretsError("unknown stdin import kind")
    result = {}
    for key, value in encoded.items():
        if not isinstance(value, str) or len(value) > 87384:
            raise SecretsError("invalid encoded import")
        try:
            result[key] = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise SecretsError("invalid base64 import") from None
        if len(result[key]) > 65536:
            raise SecretsError("decoded import exceeds size limit")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ensure", "rotate", "import"))
    parser.add_argument("--secrets-dir", default="/secrets")
    parser.add_argument("--project", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--stdin-json", action="store_true")
    for key in IMPORT_KEYS:
        parser.add_argument("--" + key.replace("_", "-"))
    args = parser.parse_args(argv)
    try:
        data = decode_stdin(sys.stdin.buffer.read(600001)) if args.stdin_json else None
        manage(args.command, args.secrets_dir, args.project, args.owner,
               imports={key: getattr(args, key) for key in IMPORT_KEYS if getattr(args, key)}, import_data=data)
    except SecretsError as error:
        print("feilian secrets: " + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("feilian secrets: helper filesystem operation failed", file=sys.stderr)
        return 2
    print("feilian secrets: prepared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
