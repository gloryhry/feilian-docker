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
        self.present = set()
        self.pull_ok = True
        self.fail_run_sh = set()
        self.container_image = ""

    def fake_run(self, argv, check=True):
        self.calls.append(list(argv))
        cmd = list(argv)
        if cmd[:2] == ["docker", "image"] and "--format" in cmd:
            ref = cmd[-1]
            return subprocess.CompletedProcess(argv, 0, json.dumps(
                [ref.split(":")[0] + "@sha256:" + "a" * 64]) + "\n", "")
        if cmd[:3] == ["docker", "image", "inspect"]:
            ref = cmd[-1]
            if ref in self.present:
                return subprocess.CompletedProcess(argv, 0, "{}", "")
            return subprocess.CompletedProcess(argv, 1, "", "No such image")
        if cmd[:2] == ["docker", "pull"]:
            if self.pull_ok:
                self.present.add(cmd[-1])
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "denied: pull failed")
        if cmd[:3] == ["docker", "inspect", "--format"]:
            if self.container_image:
                return subprocess.CompletedProcess(argv, 0, self.container_image, "")
            return subprocess.CompletedProcess(argv, 1, "", "no such container")
        if cmd[0] == "bash":  # run.sh
            target = next((a.split("=", 1)[1] for a in cmd if a.startswith("IMAGE_REF=")), "")
            if target in self.fail_run_sh:
                return subprocess.CompletedProcess(argv, 1, "", "preflight failed")
            return subprocess.CompletedProcess(argv, 0, "", "")
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

    def test_apply_pulls_the_digest_before_stopping_the_service(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
        pulls = [c for c in self.calls if c[:2] == ["docker", "pull"]]
        removals = [c for c in self.calls if c[:3] == ["docker", "rm", "--force"]]
        self.assertEqual(len(pulls), 1)
        self.assertEqual(len(removals), 1)
        # The pull must come before the container is removed, or a failed pull
        # leaves the service down for nothing.
        self.assertLess(self.calls.index(pulls[0]), self.calls.index(removals[0]))

    def test_apply_leaves_the_container_running_when_pull_fails(self):
        self.pull_ok = False
        with self.patched(), self.assertRaises(deploy.DeployError) as caught:
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
        self.assertIn("left untouched", str(caught.exception))
        self.assertEqual([c for c in self.calls if c[:3] == ["docker", "rm", "--force"]], [])
        self.assertFalse((self.root / ".state" / "feilian" / "deploy.json").exists())

    def test_apply_rolls_back_automatically_when_the_new_version_fails_to_start(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
            self.fail_run_sh = {DIGEST_B}
            with self.assertRaises(deploy.DeployError) as caught:
                deploy.apply("feilian", DIGEST_B, self.root, dry_run=False)
        self.assertIn("rolled back", str(caught.exception))
        record = json.loads((self.root / ".state" / "feilian" / "deploy.json").read_text())
        self.assertEqual(record["digest"], DIGEST_A)
        self.assertEqual(record["state"], "rolled_back")
        starts = [c for c in self.calls if c[0] == "bash"]
        self.assertEqual(len(starts), 3)  # A, B, then A again

    def test_apply_marks_failure_when_there_is_no_rollback_target(self):
        self.fail_run_sh = {DIGEST_A}
        with self.patched(), self.assertRaises(deploy.DeployError) as caught:
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
        self.assertIn("no previous digest", str(caught.exception))
        record = json.loads((self.root / ".state" / "feilian" / "deploy.json").read_text())
        self.assertEqual(record["state"], "failed")

    def test_rollback_also_pulls_before_stopping(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
            deploy.apply("feilian", DIGEST_B, self.root, dry_run=False)
            self.present.clear()  # simulate a pruned local store
            deploy.rollback("feilian", self.root, dry_run=False)
        pulls = [c for c in self.calls if c[:2] == ["docker", "pull"]]
        self.assertIn(DIGEST_A, [p[-1] for p in pulls])

    def test_plan_flags_drift_between_record_and_running_container(self):
        with self.patched():
            deploy.apply("feilian", DIGEST_A, self.root, dry_run=False)
            self.container_image = DIGEST_B  # somebody ran a different image by hand
            out = deploy.plan("feilian", DIGEST_A, self.root)
        self.assertTrue(out["divergence"])

    def test_cli_requires_confirmation_flag(self):
        with self.patched():
            code = deploy.main(["apply", "--image", DIGEST_A, "--root", str(self.root)])
        self.assertEqual(code, 2)

    def test_invalid_image_reference_is_rejected(self):
        with self.patched(), self.assertRaises(deploy.DeployError):
            deploy.plan("feilian", "bad image;rm -rf /", self.root)


if __name__ == "__main__":
    unittest.main()
