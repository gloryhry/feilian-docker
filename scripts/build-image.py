#!/usr/bin/env python3
"""Plan/build isolated FeiLian targets with validated config and locked artifacts.

Dry runs do not execute Docker, download packages, or create output directories.
Builders, binfmt handlers, registry credentials and host networking are never
created or repaired automatically. A push always requires the --push flag.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
ARCHES = ("amd64", "arm64")
CONFIG_KEYS = {
    "IMAGE_REF", "CLIENT_MANIFEST", "BUILD_PLATFORMS", "BUILD_OUTPUT",
    "BUILD_NETWORK", "DEBIAN_MIRROR", "NO_CACHE",
}


class BuildError(Exception):
    """A build request failed validation before execution."""


def json_command(command: list[str], description: str, timeout: int | None = 60) -> Any:
    try:
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BuildError(f"{description} could not run") from exc
    if result.returncode:
        # Do not echo input configuration or arbitrary subprocess output. The
        # individual validator CLI can be run directly for safe diagnostics.
        raise BuildError(f"{description} failed (exit {result.returncode}); run its validator directly")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise BuildError(f"{description} did not return valid JSON") from exc


def validated_config(args: argparse.Namespace) -> dict[str, str]:
    command = [sys.executable, str(ROOT / "scripts" / "config.py"), "render", "--format", "json"]
    if args.config is not None:
        command += ["--config", str(args.config.absolute())]
    for override in args.overrides:
        command += ["--set", override]
    typed = {
        "IMAGE_REF": args.image, "BUILD_PLATFORMS": args.platforms,
        "BUILD_OUTPUT": "load" if args.load else "oci" if args.output is not None else "push" if args.push else None,
        "NO_CACHE": "1" if args.no_cache else None,
    }
    for key, value in typed.items():
        if value is not None:
            command += ["--set", f"{key}={value}"]
    config = json_command(command, "validated config render")
    if (
        not isinstance(config, dict) or not CONFIG_KEYS <= set(config)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in config.items())
    ):
        raise BuildError("config render must return a flat string-valued object with build keys")
    if config["BUILD_NETWORK"] not in ("default", "host") or config["NO_CACHE"] not in ("0", "1"):
        raise BuildError("invalid validated build network/cache setting")
    return config


def platforms(value: str) -> list[str]:
    if value == "native":
        machine = platform.machine().lower()
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
        if arch is None:
            raise BuildError("unsupported native architecture; select --platform explicitly")
        return [f"linux/{arch}"]
    values = value.split(",")
    if not values or len(set(values)) != len(values) or any(item not in ("linux/amd64", "linux/arm64") for item in values):
        raise BuildError("platforms must be native or unique supported Linux platforms")
    return values


def output_path(value: Path | None) -> Path:
    if value is None:
        raise BuildError("OCI output requires an explicit --output PATH")
    if any(character in str(value) for character in (",", "\n", "\r", "\x00")):
        raise BuildError("OCI output path contains unsupported characters")
    result = value.absolute()
    # Refuse overwrites (including dangling links); never destroy an existing
    # image archive or source file as an incidental build side effect.
    if result.exists() or result.is_symlink():
        raise BuildError("OCI output already exists; select a new output path")
    for parent in result.parents:
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise BuildError("OCI output parent must be a real directory")
    return result


def public_lock(manifest: Path, artifact_cli: list[str]) -> dict[str, Any]:
    # Validation is delegated to the lock's owner. Reading public metadata here
    # lets mock builds avoid even consulting official installer cache paths.
    with manifest.open("rb") as stream:
        before = stream.read(1024 * 1024 + 1)
    if len(before) > 1024 * 1024:
        raise BuildError("manifest exceeds size limit")
    json_command(artifact_cli + ["validate", "--manifest", str(manifest), "--arch", "all"], "artifact lock validation")
    with manifest.open("rb") as stream:
        after = stream.read(1024 * 1024 + 1)
    if after != before:
        raise BuildError("manifest changed during validation; retry against a stable reviewed lock")
    data = json.loads(before)
    if not isinstance(data, dict):
        raise BuildError("validated lock must be an object")
    return data


def _mirror(value: str) -> None:
    if not value:
        return
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise BuildError("invalid Debian mirror") from exc
    if (
        not re.fullmatch(r"[A-Za-z0-9:/._~-]+", value)
        or parsed.scheme not in ("http", "https") or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment
    ):
        raise BuildError("Debian mirror must be a literal credential-free HTTP(S) base URL")


def create_plan(args: argparse.Namespace) -> dict[str, Any]:
    config = validated_config(args)
    requested = platforms(config["BUILD_PLATFORMS"])
    mode = config["BUILD_OUTPUT"]
    if mode not in ("load", "oci", "push"):
        raise BuildError("unsupported build output")
    if len(requested) > 1 and mode == "load":
        raise BuildError("multi-platform --load is unsupported; use --output PATH or --push")
    if mode == "push" and not args.push:
        raise BuildError("registry publication requires explicit --push confirmation")
    destination = output_path(args.output) if mode == "oci" else None
    _mirror(config["DEBIAN_MIRROR"])
    manifest = Path(config["CLIENT_MANIFEST"])
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    artifact_cli = [sys.executable, str(ROOT / "scripts" / "client-artifacts.py")]
    lock = public_lock(manifest, artifact_cli)
    release, image = lock["release"], config["IMAGE_REF"]
    if image == f"feilian-gui:{release['version']}":
        raise BuildError("the baseline image tag is reserved; select a wrapper image tag")
    if args.target == "mock":
        if args.push:
            raise BuildError("mock images cannot be published through this build interface")
        if args.image is None:
            raise BuildError("mock builds require an explicit --image for an isolated test tag")
        if image == f"feilian-gui:{release['version']}-wrapper-dev":
            raise BuildError("mock must not overwrite the default production wrapper tag")

    command = [
        "docker", "buildx", "build", "--file", str(ROOT / "Dockerfile"),
        "--target", args.target, "--platform", ",".join(requested), "--tag", image,
    ]
    if mode == "load":
        command.append("--load")
    elif mode == "push":
        command.append("--push")
    else:
        command += ["--output", f"type=oci,dest={destination}"]
    if config["BUILD_NETWORK"] == "host":
        # This is build-time networking only and never enables runtime host mode.
        command += ["--network", "host"]
    if config["NO_CACHE"] == "1":
        command.append("--no-cache")
    build_args = {
        "BASE_IMAGE": lock["base_image"], "CLIENT_VERSION": release["version"],
        "CLIENT_REVISION": release["revision"],
    }
    if config["DEBIAN_MIRROR"]:
        build_args["DEBIAN_MIRROR"] = config["DEBIAN_MIRROR"]
    preparation: list[list[str]] = []
    if args.target == "production":
        architectures = [item.split("/", 1)[1] for item in requested]
        fetch = artifact_cli + [
            "fetch", "--manifest", str(manifest), "--arch",
            "all" if len(architectures) == 2 else architectures[0],
        ]
        if args.offline:
            fetch.append("--offline")
        if args.dry_run:
            fetch.append("--dry-run")
        preparation.append(fetch)
        json_command(fetch, "locked artifact fetch", timeout=None)
        exported = json_command(
            artifact_cli + ["export", "--manifest", str(manifest), "--arch", "all", "--format", "json"],
            "locked artifact export",
        )
        if not isinstance(exported, dict) or set(exported) != set(ARCHES):
            raise BuildError("artifact export must describe exactly amd64 and arm64")
        client_root = ROOT / "dist" / release["version"]
        for arch in ARCHES:
            values = exported[arch]
            artifact = lock["artifacts"][arch]
            expected = {
                "BASE_IMAGE": lock["base_image"], "CLIENT_VERSION": release["version"],
                "CLIENT_REVISION": release["revision"], "CLIENT_ARCH": arch,
                "CLIENT_DEB_PATH": str(client_root / arch / "client.deb"),
                "CLIENT_DEB_SHA256": artifact["sha256"],
                "CLIENT_DEB_PACKAGE": artifact["deb_package"],
                "CLIENT_DEB_VERSION": artifact["deb_version"], "CLIENT_DEB_ARCHITECTURE": arch,
            }
            if values != expected:
                raise BuildError("artifact export does not match the reviewed lock/cache layout")
            build_args[f"CLIENT_SHA256_{arch.upper()}"] = values["CLIENT_DEB_SHA256"]
        build_args["CLIENT_DEB_PACKAGE"] = exported["amd64"]["CLIENT_DEB_PACKAGE"]
        build_args["CLIENT_DEB_VERSION"] = exported["amd64"]["CLIENT_DEB_VERSION"]
        command += ["--build-context", f"client_dist={client_root}"]
    else:
        fixtures = ROOT / "tests" / "fixtures" / "mock"
        if not args.dry_run:
            for name in ("corplink", "corplink-service"):
                entry = fixtures / "client" / name
                if not entry.is_file() or entry.is_symlink():
                    raise BuildError("mock fixture context is missing its regular client entrypoints")
        command += ["--build-context", f"test_fixtures={fixtures}"]
    for key, value in build_args.items():
        command += ["--build-arg", f"{key}={value}"]
    command.append(str(ROOT))
    return {
        "target": args.target, "image": image, "platforms": requested,
        "build_network": config["BUILD_NETWORK"], "output_mode": mode,
        "oci_path": str(destination) if destination is not None else None,
        "preparation": preparation, "docker_argv": command,
        "notice": "No builder/binfmt setup, registry login, or runtime host-network fallback is performed.",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path)
    result.add_argument("--set", dest="overrides", action="append", default=[], metavar="KEY=VALUE")
    result.add_argument("--platform", dest="platforms", help="native, linux/amd64, linux/arm64, or both explicit platforms")
    result.add_argument("--image", help="validated IMAGE_REF override; required for mock")
    result.add_argument("--target", choices=("production", "mock"), default="production")
    output = result.add_mutually_exclusive_group()
    output.add_argument("--load", action="store_true")
    output.add_argument("--output", type=Path, metavar="OCI_PATH")
    output.add_argument("--push", action="store_true")
    result.add_argument("--offline", action="store_true", help="only verified local official packages")
    result.add_argument("--dry-run", action="store_true", help="print JSON plan, no Docker/network/writes")
    result.add_argument("--no-cache", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        plan = create_plan(args)
        if args.dry_run:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if plan["oci_path"] is not None:
            destination = output_path(Path(plan["oci_path"]))
            destination.parent.mkdir(parents=True, exist_ok=True)
        # Use only the user's existing Buildx installation/builder. In particular,
        # do not repair missing platform support by installing privileged binfmt.
        return subprocess.run(plan["docker_argv"], cwd=ROOT, check=False).returncode
    except (BuildError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"feilian build: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("feilian build: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
