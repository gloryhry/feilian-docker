"""Run the real lifecycle wrappers against command stubs, never a daemon."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DOCKER_STUB = r'''#!/usr/bin/python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FEILIAN_CALL_LOG"], "a") as out:
    out.write(json.dumps(["docker", *args]) + "\n")
if args[:2] == ["image", "inspect"]:
    if "--format" in args:
        fmt = args[args.index("--format") + 1]
        if "runtime.schema" in fmt:
            print(os.environ.get("FEILIAN_TEST_SCHEMA", "1"))
        else:
            print(os.environ.get("FEILIAN_TEST_FEATURES", "web-auth,web-tls"))
    else:
        print("{}")
    sys.exit(0)
if args[:1] == ["compose"]:
    if "config" in args and os.environ.get("FEILIAN_TEST_BAD_COMPOSE") == "1":
        sys.exit(2)
    sys.exit(0)
if args[:1] == ["run"]:
    sys.exit(7 if os.environ.get("FEILIAN_TEST_PROBE_FAIL") == "1" else 0)
raise SystemExit("unexpected docker stub invocation")
'''
PYTHON_STUB = r'''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args and Path(args[0]).name == "network-resources.py":
    with open(os.environ["FEILIAN_CALL_LOG"], "a") as out:
        out.write(json.dumps(["network", *args[1:]]) + "\n")
    print('{"test_stub": true}')
    sys.exit(0)
os.execv("/usr/bin/python3", ["/usr/bin/python3", *args])
'''


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-lifecycle-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        for name, content in (("docker", DOCKER_STUB), ("python3", PYTHON_STUB)):
            path = self.bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o700)
        self.log = self.directory / "calls.jsonl"
        self.config = self.directory / "settings.env"
        self.config.write_text("PROJECT_NAME=lifecycle-test\nPROBE_TIMEOUT=1\n", encoding="utf-8")
        self.env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.directory),
                    "LC_ALL": "C.UTF-8", "FEILIAN_CALL_LOG": str(self.log)}

    def call(self, script, *args, extra_env=None):
        return subprocess.run(["bash", str(ROOT / script), "--config", str(self.config), *args],
            cwd=self.directory, env={**self.env, **(extra_env or {})}, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_dry_run_never_invokes_system_tools(self):
        result = self.call("run.sh", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lifecycle-test-net", result.stdout)
        self.assertIn("DRY RUN", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_bridge_failure_never_falls_back_or_removes_existing_service(self):
        result = self.call("run.sh", extra_env={"FEILIAN_TEST_PROBE_FAIL": "1"})
        self.assertEqual(result.returncode, 1, result.stderr)
        calls = self.calls()
        self.assertTrue(any(c[:2] == ["network", "ensure-bridge"] for c in calls))
        probes = [c for c in calls if c[:2] == ["docker", "run"]]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(c[c.index("--network") + 1] == "lifecycle-test-net" for c in probes))
        self.assertFalse(any(c[:2] == ["docker", "rm"] for c in calls))
        self.assertFalse(any(c[0] == "docker" and "up" in c for c in calls))
        self.assertFalse(any("host" == value for c in calls for value in c))
        self.assertIn("host was NOT selected", result.stderr)

    def test_auto_is_isolated_bridge_not_permission_escalation(self):
        result = self.call("run.sh", "--set", "NET_MODE=auto",
                           extra_env={"FEILIAN_TEST_PROBE_FAIL": "1"})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(all("host" not in c for c in self.calls()))

    def test_success_uses_validated_project_and_env_file(self):
        result = self.call("run.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        up = next(c for c in calls if c[:2] == ["docker", "compose"] and "up" in c)
        self.assertEqual(up[up.index("--project-name") + 1], "lifecycle-test")
        self.assertEqual(up[up.index("--env-file") + 1], "/dev/null")
        self.assertIn(str(ROOT / "compose.yaml"), up)
        self.assertIn("http://127.0.0.1:6080/", result.stdout)
        self.assertFalse(any(c[:2] == ["network", "apply"] for c in calls))

    def test_prepare_network_is_explicit_and_before_probe(self):
        result = self.call("run.sh", "--prepare-network")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        apply_index = next(i for i, c in enumerate(calls) if c[:2] == ["network", "apply"])
        probe_index = next(i for i, c in enumerate(calls) if c[:2] == ["docker", "run"])
        self.assertLess(apply_index, probe_index)

    def test_bad_config_does_not_invoke_docker(self):
        result = self.call("run.sh", "--set", "NOVNC_HOST_PORT=99999")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_compose_preflight_failure_precedes_network_changes(self):
        result = self.call("run.sh", extra_env={"FEILIAN_TEST_BAD_COMPOSE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[0] == "network" for c in self.calls()))
        self.assertFalse(any(c[:2] == ["docker", "run"] for c in self.calls()))

    def test_old_image_cannot_start_under_new_safety_contract(self):
        result = self.call("run.sh", extra_env={"FEILIAN_TEST_SCHEMA": "<no value>"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(any(c[0] == "network" for c in self.calls()))
        self.assertFalse(any("up" in c for c in self.calls()))

    def test_missing_web_auth_feature_refuses_start(self):
        result = self.call("run.sh", extra_env={"FEILIAN_TEST_FEATURES": "artifact-lock"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(any("up" in c for c in self.calls()))

    def test_host_requires_explicit_permission(self):
        result = self.call("run.sh", "--set", "NET_MODE=host")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_host_does_not_create_probe_or_mutate_network(self):
        result = self.call("run.sh", "--set", "NET_MODE=host", "--set", "ALLOW_HOST_NETWORK=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[0] == "network" or c[:2] == ["docker", "run"] for c in self.calls()))
        self.assertIn(str(ROOT / "compose.host.yaml"), next(c for c in self.calls() if "up" in c))

    def test_host_rejects_prepare_network_even_with_permission(self):
        result = self.call("run.sh", "--set", "NET_MODE=host", "--set", "ALLOW_HOST_NETWORK=1", "--prepare-network")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_stop_default_is_graceful_and_preserves_network_and_volumes(self):
        result = self.call("stop.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("stop", calls[0])
        self.assertNotIn("down", calls[0])
        self.assertNotIn("-v", calls[0])
        self.assertNotIn("rm", calls[0])

    def test_cleanup_is_explicit_scoped_and_never_deletes_volumes(self):
        result = self.call("stop.sh", "--cleanup-network")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertIn("down", calls[0])
        self.assertNotIn("-v", calls[0])
        self.assertEqual(calls[1][:2], ["network", "cleanup"])
        self.assertIn("lifecycle-test", calls[1])
        self.assertNotIn("--include-macvlan", calls[1])

    def test_stop_dry_run_has_no_commands(self):
        result = self.call("stop.sh", "--dry-run", "--cleanup-network")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_macvlan_cleanup_flag_requires_cleanup_request(self):
        result = self.call("stop.sh", "--include-macvlan")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
