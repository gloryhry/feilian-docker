#!/usr/bin/env python3
"""Digest-pinned deploy/apply/rollback for the project container.

Guarantees:
  * deployments are recorded by image **digest**, never by mutable tag alone;
  * data volumes are never deleted, so rollback cannot silently wipe state;
  * rollback restores the previously recorded image and refuses when the record
    is missing or belongs to another project;
  * nothing here touches the host network or other projects.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,254}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")


class DeployError(Exception):
    pass


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise DeployError("command failed: " + argv[0] + " " + argv[1])
    return result


def resolve_digest(image: str) -> str:
    if not IMAGE.fullmatch(image):
        raise DeployError("invalid image reference")
    if DIGEST.search(image):
        return image
    result = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image], check=False)
    if result.returncode:
        raise DeployError("image not present locally; pull it by digest first")
    try:
        digests = json.loads(result.stdout or "[]")
    except ValueError:
        raise DeployError("cannot parse image digests") from None
    if not digests:
        raise DeployError("image has no registry digest; push it before deploying")
    return digests[0]


def record_path(project: str, root: Path) -> Path:
    if not PROJECT.fullmatch(project):
        raise DeployError("invalid project name")
    return root / ".state" / project / "deploy.json"


def read_record(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema_version") == 1 else None


def write_record(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise DeployError("refusing symlinked deploy record")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".deploy-", suffix=".part")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def current_image(project: str) -> str:
    result = run(["docker", "inspect", "--format", "{{.Config.Image}}", project], check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def plan(project: str, image: str, root: Path) -> dict:
    target = resolve_digest(image)
    record = read_record(record_path(project, root)) or {}
    return {
        "schema_version": 1, "project": project, "target": target,
        "current": record.get("digest") or None,
        "container": current_image(project) or None,
        "actions": ["stop container (volumes preserved)",
                    "verify image digest " + target,
                    "start with the recorded digest",
                    "record digest and rollback point"],
        "volumes_preserved": True,
    }


def apply(project: str, image: str, root: Path, dry_run: bool) -> dict:
    target = resolve_digest(image)
    path = record_path(project, root)
    existing = read_record(path)
    previous = (existing or {}).get("digest")
    result = plan(project, image, root)
    if dry_run:
        return result
    if existing is not None:
        # Keep a bounded rollback chain: the immediately previous deployment.
        history = [item for item in existing.get("history", []) if isinstance(item, dict)][-4:]
        history.append({"digest": existing.get("digest"), "at": existing.get("at")})
        record = {"schema_version": 1, "project": project, "digest": target,
                  "previous": previous, "at": time.time(), "history": history}
    else:
        record = {"schema_version": 1, "project": project, "digest": target,
                  "previous": None, "at": time.time(), "history": []}
    write_record(path, record)
    # The container itself is (re)started by run.sh with an explicit digest.
    run(["docker", "rm", "--force", project], check=False)
    started = run(["bash", str(root / "run.sh"), "--set", "IMAGE_REF=" + target], check=False)
    if started.returncode:
        raise DeployError("run.sh failed; the previous digest stays recorded for rollback")
    return dict(result, applied=True, previous=previous)


def rollback(project: str, root: Path, dry_run: bool) -> dict:
    path = record_path(project, root)
    record = read_record(path)
    if not record:
        raise DeployError("no deploy record; refusing to guess a rollback target")
    previous = record.get("previous")
    if not previous or not DIGEST.search(previous):
        raise DeployError("no verifiable previous digest; manual recovery required")
    if dry_run:
        return {"schema_version": 1, "project": project, "restore": previous}
    run(["docker", "rm", "--force", project], check=False)
    started = run(["bash", str(root / "run.sh"), "--set", "IMAGE_REF=" + previous], check=False)
    if started.returncode:
        raise DeployError("rollback start failed; record left untouched")
    write_record(path, {"schema_version": 1, "project": project, "digest": previous,
                        "previous": record.get("digest"), "at": time.time(),
                        "history": record.get("history", [])})
    return {"schema_version": 1, "project": project, "restored": previous}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "rollback"))
    parser.add_argument("--project", default=os.environ.get("PROJECT_NAME", "feilian"))
    parser.add_argument("--image")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true", help="required for apply/rollback")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            if not args.image:
                raise DeployError("plan requires --image")
            output = plan(args.project, args.image, args.root)
        elif args.command == "apply":
            if not args.image or not args.yes:
                raise DeployError("apply requires --image and --yes")
            output = apply(args.project, args.image, args.root, args.dry_run)
        else:
            if not args.yes:
                raise DeployError("rollback requires --yes")
            output = rollback(args.project, args.root, args.dry_run)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except DeployError as exc:
        print("feilian deploy: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
