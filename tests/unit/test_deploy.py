"""Offline deploy/rollback tests: docker and run.sh are command stubs."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("deploy", ROOT / "scripts" / "deploy.py")
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)

DIGEST_A = "example.invalid/app@sha256:" + "a" * 64
DIGEST_B = "example.invalid/app@sha256:" + "b" * 64


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="deploy-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.calls = []

    def fake_run(self, argv, check=True):
        self.calls.append(list(argv))
        if argv[:2] == ["docker", "image"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps([argv[-1].split(":")[0] + "@sha256:" + "a" * 64]) + "\n", "")
        if argv[:3] == ["docker", "inspect", "--format"]:
            return subprocess.CompletedProcess(argv, 1, "", "no such container")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def patched(self):
        return mock.patch.object(deploy, "run", side_effect=self.fake_run)

    def test_plan_resolves_mutable_tag_to_digest(self):
        with self.patched():
            out = deploy.plan("feilian", "example.invalid/app:latest", self.root)
        self.assertIn("@sha256:", out["target"])
        self.assertTrue(out["volumes_preserved"])
        self.assertFalse((self.root / ".state").exists())

    def test_digest_pinned_reference_is_used_verbatim(self):
        with self.patched():
            out = deploy.plan("feilian", DIGEST_B, self.root)
        self.assertEqual(out["target"], DIGEST_B)

    def test_apply_requires_verifiable_digest_and_records_previous(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
            record = json.loads((self.root / ".state" / "feilian" / "deploy.json").read_text())
            self.assertEqual(record["digest"], DIGEST_A)
            self.assertIsNone(record["previous"])
            deploy.apply("feilian", DIGEST_B, self.root, dry_run=False)
            record = json.loads((self.root / ".state" / "feilian" / "deploy.json").read_text())
        self.assertEqual(record["digest"], DIGEST_B)
        self.assertEqual(record["previous"], DIGEST_A)
        self.assertEqual((self.root / ".state" / "feilian" / "deploy.json").stat().st_mode & 0o777, 0o600)
        # Volumes are never deleted by deploy.
        self.assertFalse(any("volume" in " ".join(call) for call in self.calls))

    def test_rollback_restores_previous_digest_and_refuses_without_record(self):
        with self.patched():
            with self.assertRaises(deploy.DeployError):
                deploy.rollback("feilian", self.root, dry_run=False)
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
            with self.assertRaises(deploy.DeployError):
                deploy.rollback("feilian", self.root, dry_run=False)  # nothing to go back to
            deploy.apply("feilian", DIGEST_B, self.root, dry_run=False)
            out = deploy.rollback("feilian", self.root, dry_run=False)
        self.assertEqual(out["restored"], DIGEST_A)
        record = json.loads((self.root / ".state" / "feilian" / "deploy.json").read_text())
        self.assertEqual(record["digest"], DIGEST_A)

    def test_other_project_record_is_not_reused(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
        self.assertFalse((self.root / ".state" / "other" / "deploy.json").exists())

    def test_symlinked_record_is_refused(self):
        state = self.root / ".state" / "feilian"
        state.mkdir(parents=True)
        outside = self.root / "outside.json"
        outside.write_text("{}")
        (state / "deploy.json").symlink_to(outside)
        with self.patched(), self.assertRaises(deploy.DeployError):
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)

    def test_cli_requires_confirmation_flag(self):
        with self.patched():
            code = deploy.main(["apply", "--image", DIGEST_A, "--root", str(self.root)])
        self.assertEqual(code, 2)

    def test_invalid_image_reference_is_rejected(self):
        with self.patched(), self.assertRaises(deploy.DeployError):
            deploy.plan("feilian", "bad image;rm -rf /", self.root)


if __name__ == "__main__":
    unittest.main()
