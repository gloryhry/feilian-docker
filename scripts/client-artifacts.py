#!/usr/bin/env python3
"""Validate and fetch maintainer-reviewed, byte-pinned FeiLian packages.

Only the Python standard library is used. curl handles HTTPS through the caller's
normal proxy environment, and dpkg-deb reads package headers without installing or
executing package contents. Neither discovery nor downloads can approve a hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARCHITECTURES = ("amd64", "arm64")
MANIFEST_LIMIT = 1024 * 1024
PACKAGE_LIMIT = 1024 * 1024 * 1024
DISCOVERY_LIMIT = 16 * 1024 * 1024
DISCOVERY_URL = (
    "https://lf6-cdn2-tos.bytegoofy.com/gftar/toutiao/fe_arch/"
    "fes2_app_17848070966032730/1.0.0.15/bundles/js/main.js"
)
ROOT_KEYS = {"schema_version", "release", "base_image", "artifacts"}
ARTIFACT_KEYS = {
    "filename", "url", "sha256", "deb_package", "deb_version",
    "deb_architecture", "verification",
}
FILENAME_PATTERN = re.compile(
    r"FeiLian_Linux_(amd64|arm64)_v([0-9]+\.[0-9]+\.[0-9]+)_"
    r"(r[0-9]+)_([0-9a-f]{6})\.deb"
)


class ArtifactError(Exception):
    """An invalid lock, cache entry, or failed download (always fail closed)."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _keys(value: Any, expected: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ArtifactError(f"{where}: expected exactly {', '.join(sorted(expected))}")


def _matches(value: Any, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def official_package_url(url: Any, filename: str) -> None:
    if not isinstance(url, str):
        raise ArtifactError("artifact URL must be a string")
    # Exact reconstruction rejects credentials, ports, queries, fragments,
    # percent-encoded paths, alternate hosts, traversal, and HTTP downgrades.
    expected = f"https://cdn.isealsuite.com/linux/{filename}"
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ArtifactError("invalid artifact URL") from exc
    if (
        url != expected or parsed.scheme != "https"
        or parsed.netloc != "cdn.isealsuite.com"
        or parsed.path != f"/linux/{filename}" or parsed.query or parsed.fragment
    ):
        raise ArtifactError("artifact URL must be the exact allowlisted official HTTPS URL")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MANIFEST_LIMIT + 1)
        if len(raw) > MANIFEST_LIMIT:
            raise ArtifactError("manifest exceeds size limit")
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read valid JSON manifest: {path}") from exc
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Any) -> None:
    _keys(manifest, ROOT_KEYS, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ArtifactError("schema_version must be integer 1")
    release = manifest["release"]
    _keys(release, {"version", "revision"}, "release")
    if not _matches(release["version"], r"[0-9]+\.[0-9]+\.[0-9]+"):
        raise ArtifactError("release.version must have three numeric components")
    if not _matches(release["revision"], r"r[0-9]+"):
        raise ArtifactError("release.revision must be r followed by digits")
    if not _matches(manifest["base_image"], r"debian:trixie-slim@sha256:[0-9a-f]{64}"):
        raise ArtifactError("base_image must pin the reviewed Debian trixie-slim index digest")
    _keys(manifest["artifacts"], set(ARCHITECTURES), "artifacts")
    for arch in ARCHITECTURES:
        artifact = manifest["artifacts"][arch]
        _keys(artifact, ARTIFACT_KEYS, f"artifacts.{arch}")
        filename = artifact["filename"]
        match = FILENAME_PATTERN.fullmatch(filename) if isinstance(filename, str) else None
        if not match or match.groups()[:3] != (arch, release["version"], release["revision"]):
            raise ArtifactError(f"{arch}: filename does not match architecture/version/revision")
        official_package_url(artifact["url"], filename)
        if not _matches(artifact["sha256"], r"[0-9a-f]{64}"):
            raise ArtifactError(f"{arch}: sha256 must be a full lowercase 64-hex digest")
        if artifact["deb_package"] != "com.volcengine.feilian":
            raise ArtifactError(f"{arch}: unexpected DEB package name")
        if artifact["deb_version"] != release["version"]:
            raise ArtifactError(f"{arch}: DEB version must match release.version")
        if artifact["deb_architecture"] != arch:
            raise ArtifactError(f"{arch}: DEB architecture must match manifest architecture")
        verification = artifact["verification"]
        _keys(verification, {"method", "reference", "approved"}, f"{arch}.verification")
        if (
            verification["method"] != "maintainer-reviewed-tls"
            or verification["approved"] is not True
            or verification["reference"] != artifact["url"]
        ):
            raise ArtifactError(f"{arch}: explicit maintainer-reviewed official TLS approval required")


def selected_architectures(value: str | None) -> tuple[str, ...]:
    if value == "all":
        return ARCHITECTURES
    if value in ARCHITECTURES:
        return (value,)
    machine = platform.machine().lower()
    normalized = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if machine not in normalized:
        raise ArtifactError(f"unsupported host architecture {machine!r}; select --arch explicitly")
    return (normalized[machine],)


def _check_cache_path(path: Path) -> None:
    """Reject links/special files in every existing cache path component."""
    try:
        parts = path.relative_to(PROJECT_ROOT).parts
    except ValueError as exc:
        raise ArtifactError("cache path escapes project root") from exc
    current = PROJECT_ROOT
    for index, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise ArtifactError("invalid cache path component")
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ArtifactError(f"refusing symlink in cache path: {current}")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ArtifactError(f"cache parent is not a directory: {current}")
        elif not stat.S_ISREG(info.st_mode):
            raise ArtifactError(f"cache entry is not a regular file: {current}")


def cache_path(manifest: dict[str, Any], arch: str) -> Path:
    result = PROJECT_ROOT / "dist" / manifest["release"]["version"] / arch / "client.deb"
    _check_cache_path(result)
    return result


def verify_package(path: Path, artifact: dict[str, Any]) -> None:
    _check_cache_path(path)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ArtifactError(f"cannot read package: {path}") from exc
    if digest.hexdigest() != artifact["sha256"]:
        raise ArtifactError(f"SHA256 mismatch: {path}")
    try:
        header = subprocess.run(
            ["dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactError("cannot read DEB header; dpkg-deb is required") from exc
    if header.returncode != 0:
        raise ArtifactError(f"invalid DEB header: {path}")
    expected = {
        "Package": artifact["deb_package"],
        "Version": artifact["deb_version"],
        "Architecture": artifact["deb_architecture"],
    }
    fields: dict[str, str] = {}
    for line in header.stdout.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key in fields:
            raise ArtifactError(f"invalid or duplicate DEB control field: {path}")
        fields[key] = value.strip()
    if fields != expected:
        raise ArtifactError(f"DEB package/version/architecture mismatch: {path}")


def _curl_options(maximum_size: int) -> list[str]:
    # --disable must be the first curl argument: ~/.curlrc cannot turn off TLS
    # verification, inject credentials, or enable unreviewed redirects.
    return [
        "curl", "--disable", "--fail", "--silent", "--show-error",
        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--connect-timeout", "15", "--max-time", "1200", "--retry", "3",
        "--retry-delay", "2", "--retry-max-time", "2400", "--retry-all-errors",
        "--max-redirs", "0",
        "--max-filesize", str(maximum_size),
    ]


def _download(url: str, destination: Path) -> None:
    """Download with resume.

    The arm64 package is ~179 MB and the CDN is not always fast; a single
    `--max-time` budget made CI flaky and left users re-downloading from zero.
    Each attempt continues from whatever was already fetched, and only a
    complete, correct file is ever published (verification happens later).
    """
    attempts = 3
    last_code = ""
    for attempt in range(1, attempts + 1):
        options = _curl_options(PACKAGE_LIMIT)
        resuming = destination.exists() and destination.stat().st_size > 0
        if resuming:
            options += ["--continue-at", "-"]
        try:
            result = subprocess.run(
                options + ["--output", str(destination), "--write-out", "%{http_code}",
                           "--url", url],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=1800, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArtifactError("curl download failed or timed out") from exc
        last_code = result.stdout.strip()
        if result.returncode == 0 and last_code in ("200", "206"):
            if destination.stat().st_size > PACKAGE_LIMIT:
                raise ArtifactError("download exceeds package size limit")
            return
        if result.returncode != 0 and attempt == attempts:
            # Do not echo curl stderr: proxy configuration might contain credentials.
            raise ArtifactError(f"curl download failed (exit {result.returncode})")
        if attempt < attempts:
            time.sleep(min(10, 2 ** attempt))
    raise ArtifactError("download did not return HTTP 200/206; redirects are not followed")


def _publish(manifest: dict[str, Any], arch: str, source: Path | None) -> Path:
    target = cache_path(manifest, arch)
    target.parent.mkdir(parents=True, exist_ok=True)
    _check_cache_path(target)
    fd, temporary_name = tempfile.mkstemp(prefix=".client-", suffix=".part", dir=target.parent)
    temporary = Path(temporary_name)
    os.close(fd)
    try:
        if source is not None:
            with source.open("rb") as original, temporary.open("wb") as output:
                shutil.copyfileobj(original, output, length=1024 * 1024)
        else:
            _download(manifest["artifacts"][arch]["url"], temporary)
        verify_package(temporary, manifest["artifacts"][arch])
        os.chmod(temporary, 0o644)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        # Both paths are checked before the only rename; legacy files are never
        # moved, and no unverified bytes are ever published as client.deb.
        _check_cache_path(temporary)
        _check_cache_path(target)
        os.replace(temporary, target)
        return target
    finally:
        # Only our own unique, checked temporary path is eligible for cleanup.
        _check_cache_path(temporary)
        temporary.unlink(missing_ok=True)


def fetch_artifacts(
    manifest: dict[str, Any], architectures: tuple[str, ...], *,
    offline: bool = False, dry_run: bool = False,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for arch in architectures:
        artifact = manifest["artifacts"][arch]
        target = cache_path(manifest, arch)
        if target.exists():
            verify_package(target, artifact)
            status = "cached"
        else:
            legacy = PROJECT_ROOT / "dist" / artifact["filename"]
            _check_cache_path(legacy)
            if legacy.exists():
                verify_package(legacy, artifact)
                status = "would-copy" if dry_run else "copied"
                if not dry_run:
                    _publish(manifest, arch, legacy)
            else:
                if offline:
                    raise ArtifactError(f"offline cache miss for {arch}: {target}")
                status = "would-download" if dry_run else "downloaded"
                if not dry_run:
                    _publish(manifest, arch, None)
        results[arch] = {"status": status, "path": str(target), "sha256": artifact["sha256"]}
    return results


def export_values(manifest: dict[str, Any], arch: str) -> dict[str, str]:
    artifact = manifest["artifacts"][arch]
    return {
        "CLIENT_VERSION": manifest["release"]["version"],
        "CLIENT_REVISION": manifest["release"]["revision"],
        "BASE_IMAGE": manifest["base_image"],
        "CLIENT_ARCH": arch,
        "CLIENT_DEB_PATH": str(cache_path(manifest, arch)),
        "CLIENT_DEB_SHA256": artifact["sha256"],
        "CLIENT_DEB_PACKAGE": artifact["deb_package"],
        "CLIENT_DEB_VERSION": artifact["deb_version"],
        "CLIENT_DEB_ARCHITECTURE": artifact["deb_architecture"],
    }


def discover() -> dict[str, Any]:
    try:
        result = subprocess.run(
            _curl_options(DISCOVERY_LIMIT) + ["--output", "-", "--url", DISCOVERY_URL],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactError("candidate discovery failed or timed out; no fallback is used") from exc
    if result.returncode != 0 or len(result.stdout) > DISCOVERY_LIMIT:
        raise ArtifactError("candidate discovery failed; no fallback is used")
    text = result.stdout.decode("utf-8", errors="replace")
    urls = sorted(set(re.findall(
        r"https://cdn\.isealsuite\.com/linux/FeiLian_Linux_"
        r"(?:amd64|arm64)_v[0-9]+\.[0-9]+\.[0-9]+_r[0-9]+_[0-9a-f]{6}\.deb",
        text,
    )))
    candidates = []
    for url in urls:
        filename = url.rsplit("/", 1)[-1]
        official_package_url(url, filename)
        match = FILENAME_PATTERN.fullmatch(filename)
        assert match is not None
        candidates.append({
            "url": url, "filename": filename, "architecture": match[1],
            "version": match[2], "revision": match[3], "approved": False,
        })
    if not candidates:
        raise ArtifactError("no official DEB candidates found; no fallback is used")
    return {
        "source": DISCOVERY_URL, "candidates": candidates,
        "notice": "Untrusted candidates only; no hashes approved and no lock file changed.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "fetch", "export"):
        child = commands.add_parser(command)
        child.add_argument("--manifest", type=Path, default=PROJECT_ROOT / "config" / "client.lock.json")
        child.add_argument("--arch", choices=(*ARCHITECTURES, "all"), default="all" if command == "validate" else None)
        if command == "fetch":
            child.add_argument("--offline", action="store_true", help="use verified cache/legacy packages only")
            child.add_argument("--dry-run", action="store_true", help="verify local inputs without writes or network")
        elif command == "export":
            child.add_argument("--format", choices=("json", "env"), default="json")
    commands.add_parser("discover", help="print official URL candidates; never edit or approve the lock")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "discover":
            output = discover()
        else:
            manifest = load_manifest(args.manifest)
            architectures = selected_architectures(args.arch)
            if args.command == "validate":
                output = {
                    "valid": True, "schema_version": 1,
                    "release": manifest["release"], "architectures": list(architectures),
                }
            elif args.command == "fetch":
                output = fetch_artifacts(manifest, architectures, offline=args.offline, dry_run=args.dry_run)
            else:
                if args.format == "env":
                    if len(architectures) != 1:
                        raise ArtifactError("export --format env requires a single --arch")
                    for key, value in export_values(manifest, architectures[0]).items():
                        print(f"{key}={shlex.quote(value)}")
                    return 0
                output = (
                    {arch: export_values(manifest, arch) for arch in architectures}
                    if args.arch == "all" else export_values(manifest, architectures[0])
                )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (ArtifactError, OSError) as exc:
        print(f"client-artifacts: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("client-artifacts: interrupted; no unverified package published", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
