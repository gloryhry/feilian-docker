"""Build command contract tests. Docker and artifact I/O are always local stubs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
ARTIFACT_STUB = r'''
import argparse
import json
import os
from pathlib import Path
import sys
root = Path(__file__).resolve().parent.parent
with Path(os.environ['STUB_ARTIFACT_LOG']).open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\n')
parser = argparse.ArgumentParser()
parser.add_argument('command')
parser.add_argument('--manifest', type=Path, required=True)
parser.add_argument('--arch')
parser.add_argument('--format')
parser.add_argument('--offline', action='store_true')
parser.add_argument('--dry-run', action='store_true')
args = parser.parse_args()
lock = json.loads(args.manifest.read_text())
if args.command == 'validate':
    print(json.dumps({'valid': True}))
elif args.command == 'fetch':
    if os.environ.get('STUB_FETCH_FAIL'):
        raise SystemExit(2)
    print(json.dumps({'status': 'would-download' if args.dry_run else 'cached'}))
elif args.command == 'export':
    result = {}
    for arch, artifact in lock['artifacts'].items():
        result[arch] = {
            'CLIENT_VERSION': lock['release']['version'], 'CLIENT_REVISION': lock['release']['revision'],
            'BASE_IMAGE': lock['base_image'], 'CLIENT_ARCH': arch,
            'CLIENT_DEB_PATH': str(root / 'dist' / lock['release']['version'] / arch / 'client.deb'),
            'CLIENT_DEB_SHA256': artifact['sha256'], 'CLIENT_DEB_PACKAGE': artifact['deb_package'],
            'CLIENT_DEB_VERSION': artifact['deb_version'], 'CLIENT_DEB_ARCHITECTURE': arch,
        }
    if os.environ.get('STUB_EXPORT_WRONG'):
        result['amd64']['CLIENT_DEB_PATH'] = '/outside/untrusted.deb'
    print(json.dumps(result))
else:
    raise SystemExit(92)
'''
DOCKER_STUB = r'''
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
if sys.argv[1:3] != ['buildx', 'build']:
    raise SystemExit(91)
with Path(os.environ['STUB_DOCKER_LOG']).open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\n')
raise SystemExit(int(os.environ.get('STUB_DOCKER_EXIT', '0')))
'''


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="build-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        for filename in ("build-image.py", "config.py"):
            shutil.copyfile(REPOSITORY / "scripts" / filename, scripts / filename)
        self.script = scripts / "build-image.py"
        shutil.copyfile(REPOSITORY / "build.sh", self.root / "build.sh")
        (scripts / "client-artifacts.py").write_text(textwrap.dedent(ARTIFACT_STUB))
        self.lock = self.root / "config" / "client.lock.json"
        self.lock.parent.mkdir()
        self.manifest = {
            "schema_version": 1, "release": {"version": "3.2.16", "revision": "r8362"},
            "base_image": "debian:trixie-slim@sha256:" + "a" * 64, "artifacts": {},
        }
        for arch in ("amd64", "arm64"):
            self.manifest["artifacts"][arch] = {
                "sha256": ("b" if arch == "amd64" else "c") * 64,
                "deb_package": "com.volcengine.feilian", "deb_version": "3.2.16", "deb_architecture": arch,
            }
        self.lock.write_text(json.dumps(self.manifest))
        self.bin = self.root / "stub-bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(textwrap.dedent(DOCKER_STUB).lstrip())
        docker.chmod(0o755)
        self.artifact_log = self.root / "artifact-commands.jsonl"
        self.docker_log = self.root / "docker-commands.jsonl"
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", os.defpath),
            "PYTHONDONTWRITEBYTECODE": "1", "STUB_ARTIFACT_LOG": str(self.artifact_log),
            "STUB_DOCKER_LOG": str(self.docker_log),
        }
        self.fixtures = self.root / "tests" / "fixtures" / "mock" / "client"
        self.fixtures.mkdir(parents=True)
        for name in ("corplink", "corplink-service"):
            (self.fixtures / name).write_text("#!/bin/sh\nexit 0\n")

    def cli(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [sys.executable, str(self.script), *args], cwd=self.root,
            env=self.env, capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        return result

    def plan(self, *args: str) -> dict:
        return json.loads(self.cli(*args, "--dry-run").stdout)

    def calls(self, path: Path) -> list:
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def flag_values(self, argv: list, flag: str) -> list:
        return [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == flag]

    def test_default_single_platform_load_is_safe_and_preserves_baseline(self) -> None:
        plan = self.plan("--platform", "linux/amd64")
        argv = plan["docker_argv"]
        self.assertEqual(argv[:3], ["docker", "buildx", "build"])
        self.assertEqual(plan["image"], "feilian-gui:3.2.16-wrapper-dev")
        self.assertIn("--load", argv)
        for forbidden in ("--push", "--network", "--privileged", "--allow"):
            self.assertNotIn(forbidden, argv)
        self.assertFalse(self.docker_log.exists())
        self.assertFalse((self.root / "dist").exists())
        contexts = self.flag_values(argv, "--build-context")
        self.assertEqual(contexts, [f"client_dist={self.root / 'dist' / '3.2.16'}"])
        artifact_calls = self.calls(self.artifact_log)
        self.assertEqual([call[0] for call in artifact_calls], ["validate", "fetch", "export"])
        self.assertIn("--dry-run", artifact_calls[1])
        self.assertNotIn("discover", str(artifact_calls))

    def test_explicit_arm64_has_exact_hash_and_version_arguments(self) -> None:
        plan = self.plan("--platform", "linux/arm64", "--offline")
        build_args = self.flag_values(plan["docker_argv"], "--build-arg")
        self.assertIn("CLIENT_SHA256_ARM64=" + "c" * 64, build_args)
        self.assertIn("CLIENT_SHA256_AMD64=" + "b" * 64, build_args)
        self.assertIn("CLIENT_DEB_PACKAGE=com.volcengine.feilian", build_args)
        self.assertIn("CLIENT_DEB_VERSION=3.2.16", build_args)
        self.assertIn("CLIENT_REVISION=r8362", build_args)
        self.assertIn("BASE_IMAGE=" + self.manifest["base_image"], build_args)
        fetch = self.calls(self.artifact_log)[1]
        self.assertEqual(fetch[fetch.index("--arch") + 1], "arm64")
        self.assertIn("--offline", fetch)

    def test_multiplatform_oci_is_explicit_and_dry_run_does_not_create_parent(self) -> None:
        output = self.root / "dist" / "images" / "release.oci.tar"
        plan = self.plan("--platform", "linux/amd64,linux/arm64", "--output", str(output))
        argv = plan["docker_argv"]
        self.assertEqual(self.flag_values(argv, "--output"), [f"type=oci,dest={output}"])
        self.assertNotIn("--load", argv)
        self.assertNotIn("--push", argv)
        self.assertFalse(output.parent.exists())
        fetch = self.calls(self.artifact_log)[1]
        self.assertEqual(fetch[fetch.index("--arch") + 1], "all")

    def test_multiplatform_load_and_output_option_conflicts_fail_before_artifacts(self) -> None:
        self.cli("--platform", "linux/amd64,linux/arm64", "--load", "--dry-run", expected=2)
        self.cli("--push", "--load", "--dry-run", expected=2)
        self.assertFalse(self.artifact_log.exists())
        self.assertFalse(self.docker_log.exists())

    def test_push_requires_explicit_confirmation_even_when_configured(self) -> None:
        self.env["BUILD_OUTPUT"] = "push"
        self.cli("--dry-run", expected=2)
        self.assertFalse(self.artifact_log.exists())
        plan = self.plan("--platform", "linux/amd64,linux/arm64", "--push", "--image", "example.invalid/team/feilian:review")
        self.assertIn("--push", plan["docker_argv"])
        self.assertNotIn("--load", plan["docker_argv"])
        self.assertFalse(self.docker_log.exists())

    def test_configured_oci_requires_explicit_output_path(self) -> None:
        self.env["BUILD_OUTPUT"] = "oci"
        self.cli("--dry-run", expected=2)
        self.assertFalse(self.artifact_log.exists())
        self.assertFalse(self.docker_log.exists())

    def test_build_network_host_only_appears_for_explicit_validated_opt_in(self) -> None:
        plan = self.plan("--set", "BUILD_NETWORK=host", "--platform", "linux/amd64")
        self.assertEqual(self.flag_values(plan["docker_argv"], "--network"), ["host"])
        self.assertNotIn("NET_MODE=host", str(plan))
        self.assertFalse(self.docker_log.exists())

    def test_cli_overrides_go_through_config_not_shell(self) -> None:
        path = self.root / "custom.env"
        path.write_text("IMAGE_REF=feilian-config:test\nDEBIAN_MIRROR=https://mirror.example.invalid/debian\n")
        self.env["NO_CACHE"] = "1"
        plan = self.plan("--config", str(path), "--image", "feilian-cli:review", "--platform", "linux/amd64")
        self.assertEqual(plan["image"], "feilian-cli:review")
        self.assertIn("--no-cache", plan["docker_argv"])
        self.assertIn("DEBIAN_MIRROR=https://mirror.example.invalid/debian", self.flag_values(plan["docker_argv"], "--build-arg"))
        self.cli("--image", "bad;touch/PWNED", "--dry-run", expected=2)
        self.assertFalse((self.root / "PWNED").exists())

    def test_flat_config_extra_values_are_not_disclosed_in_build_plan(self) -> None:
        data = {
            "IMAGE_REF": "feilian-gui:3.2.16-wrapper-dev", "CLIENT_MANIFEST": "config/client.lock.json",
            "BUILD_PLATFORMS": "linux/amd64", "BUILD_OUTPUT": "load", "BUILD_NETWORK": "default",
            "DEBIAN_MIRROR": "", "NO_CACHE": "0", "UNRELATED_SECRET": "PRIVATE_TEST_MARKER_NOT_A_REAL_SECRET",
        }
        config_cli = self.root / "scripts" / "config.py"
        config_cli.write_text("import json\nprint(json.dumps(" + repr(data) + "))\n")
        result = self.cli("--dry-run")
        self.assertNotIn("PRIVATE_TEST_MARKER", result.stdout + result.stderr)
        self.assertNotIn("UNRELATED_SECRET", result.stdout + result.stderr)
        data["NO_CACHE"] = 1
        config_cli.write_text("import json\nprint(json.dumps(" + repr(data) + "))\n")
        self.cli("--dry-run", expected=2)
        self.assertFalse(self.docker_log.exists())

    def test_no_cache_flag_is_validated_and_mock_fixture_missing_fails_before_docker(self) -> None:
        plan = self.plan("--platform", "linux/amd64", "--no-cache")
        self.assertIn("--no-cache", plan["docker_argv"])
        missing = self.fixtures / "corplink-service"
        self.assertEqual(missing.resolve(), self.root / "tests" / "fixtures" / "mock" / "client" / "corplink-service")
        missing.unlink()
        self.cli("--target", "mock", "--image", "feilian-mock:test", expected=2)
        self.assertFalse(self.docker_log.exists())

    def test_invalid_config_prevents_all_artifact_and_docker_commands(self) -> None:
        self.cli("--set", "UNKNOWN_KEY=1", "--dry-run", expected=2)
        self.assertFalse(self.artifact_log.exists())
        self.assertFalse(self.docker_log.exists())

    def test_mock_never_fetches_exports_or_sends_official_installer_context(self) -> None:
        self.env["STUB_FETCH_FAIL"] = "1"
        plan = self.plan("--target", "mock", "--image", "feilian-mock:test", "--platform", "linux/amd64")
        self.assertEqual([call[0] for call in self.calls(self.artifact_log)], ["validate"])
        contexts = self.flag_values(plan["docker_argv"], "--build-context")
        self.assertEqual(contexts, [f"test_fixtures={self.fixtures.parent}"])
        self.assertNotIn("client_dist=", str(plan))
        self.assertNotIn("CLIENT_SHA256", str(plan))
        self.assertFalse((self.root / "dist").exists())
        self.assertFalse(self.docker_log.exists())

    def test_mock_requires_isolated_explicit_tag_and_cannot_push(self) -> None:
        self.cli("--target", "mock", "--dry-run", expected=2)
        self.cli("--target", "mock", "--image", "feilian-gui:3.2.16-wrapper-dev", "--dry-run", expected=2)
        self.cli("--target", "mock", "--image", "feilian-mock:test", "--push", "--dry-run", expected=2)
        self.assertFalse(self.docker_log.exists())

    def test_baseline_tag_is_reserved_for_both_targets(self) -> None:
        for target in ("production", "mock"):
            self.cli("--target", target, "--image", "feilian-gui:3.2.16", "--dry-run", expected=2)
        self.assertTrue(all(call[0] == "validate" for call in self.calls(self.artifact_log)))
        self.assertFalse(self.docker_log.exists())

    def test_existing_or_comma_oci_paths_are_rejected_without_overwrite(self) -> None:
        existing = self.root / "keep.oci"
        existing.write_bytes(b"do not overwrite")
        self.cli("--output", str(existing), "--dry-run", expected=2)
        self.cli("--output", str(self.root / "x,unsafe.oci"), "--dry-run", expected=2)
        self.assertEqual(existing.read_bytes(), b"do not overwrite")
        self.assertFalse(self.docker_log.exists())
        self.assertFalse(self.artifact_log.exists())

    def test_fetch_or_export_failure_never_reaches_docker(self) -> None:
        self.env["STUB_FETCH_FAIL"] = "1"
        self.cli("--platform", "linux/amd64", "--offline", expected=2)
        self.assertFalse(self.docker_log.exists())
        self.env.pop("STUB_FETCH_FAIL")
        self.env["STUB_EXPORT_WRONG"] = "1"
        self.cli("--platform", "linux/amd64", "--offline", expected=2)
        self.assertFalse(self.docker_log.exists())

    def test_non_dry_run_invokes_only_stub_buildx_and_propagates_exit_status(self) -> None:
        self.env["STUB_DOCKER_EXIT"] = "42"
        self.cli("--platform", "linux/amd64", "--offline", expected=42)
        calls = self.calls(self.docker_log)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["buildx", "build"])
        fetch = self.calls(self.artifact_log)[1]
        self.assertIn("--offline", fetch)
        self.assertNotIn("--dry-run", fetch)

    def test_mock_stub_execution_needs_fixture_files_but_not_vendor_packages(self) -> None:
        self.cli("--target", "mock", "--image", "feilian-mock:test", "--platform", "linux/amd64")
        self.assertEqual(len(self.calls(self.docker_log)), 1)
        self.assertEqual([call[0] for call in self.calls(self.artifact_log)], ["validate"])
        self.assertFalse((self.root / "dist").exists())

    def test_shell_wrapper_preserves_arguments_from_another_directory(self) -> None:
        result = subprocess.run(
            ["bash", str(self.root / "build.sh"), "--platform", "linux/amd64", "--dry-run"],
            cwd=self.root.parent, env=self.env, capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["image"], "feilian-gui:3.2.16-wrapper-dev")
        self.assertFalse(self.docker_log.exists())

    def test_dockerfile_stages_are_separate_and_production_rechecks_exact_deb(self) -> None:
        dockerfile = (REPOSITORY / "Dockerfile").read_text()
        self.assertIn("FROM ${BASE_IMAGE} AS runtime-dependencies", dockerfile)
        self.assertIn("FROM runtime-dependencies AS runtime-base", dockerfile)
        dependencies = dockerfile.split("FROM runtime-dependencies AS runtime-base", 1)[0]
        self.assertNotIn("COPY scripts/", dependencies)
        self.assertNotIn("COPY runtime/", dependencies)
        mock = dockerfile.split("FROM runtime-base AS mock", 1)[1].split("FROM runtime-base AS production", 1)[0]
        self.assertIn("COPY --from=test_fixtures /client/", mock)
        self.assertNotIn("client_dist", mock)
        production = dockerfile.split("FROM runtime-base AS production", 1)[1]
        self.assertIn("from=client_dist", production)
        self.assertIn('deb="/tmp/feilian-dist/${TARGETARCH}/client.deb"', production)
        self.assertIn("sha256sum --check --strict", production)
        for field in ("Package", "Version", "Architecture"):
            self.assertIn(f'dpkg-deb --field "$deb" {field}', production)
        self.assertNotIn("dpkg -i", dockerfile)
        self.assertNotIn("COPY dist", dockerfile)
        self.assertNotIn("FeiLian_Linux_amd64_*", dockerfile)
        self.assertIn('io.feilian.runtime.schema="1"', dockerfile)
        features = dockerfile.split('io.feilian.features="', 1)[1].split('"', 1)[0].split(",")
        self.assertTrue({"config", "artifact-lock"} <= set(features))
        for package in ("x11-utils", "nginx-light", "openssl", "apache2-utils", "privoxy", "microsocks", "nftables", "python3"):
            self.assertIn(package, dockerfile)


if __name__ == "__main__":
    unittest.main()
