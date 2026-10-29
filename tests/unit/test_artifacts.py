"""Offline artifact contract tests: generated tiny DEBs, never vendor downloads."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]


def miniature_deb(
    architecture: str = "amd64", package: str = "com.volcengine.feilian", version: str = "3.2.16",
) -> bytes:
    """Build a deterministic ar/control/data DEB with stdlib, not package tools."""
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: Artifact Test <test@example.invalid>\nDescription: Offline fixture\n"
    ).encode()
    control_buffer = io.BytesIO()
    with tarfile.open(fileobj=control_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("control")
        info.size = len(control)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(control))
    data_buffer = io.BytesIO()
    with tarfile.open(fileobj=data_buffer, mode="w", format=tarfile.USTAR_FORMAT):
        pass
    members = (
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", gzip.compress(control_buffer.getvalue(), mtime=0)),
        ("data.tar.gz", gzip.compress(data_buffer.getvalue(), mtime=0)),
    )
    result = bytearray(b"!<arch>\n")
    for name, data in members:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n"
        assert len(header) == 60
        result.extend(header.encode("ascii"))
        result.extend(data)
        if len(data) % 2:
            result.extend(b"\n")
    return bytes(result)


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is required for header validation")
class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="artifact-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / "scripts" / "client-artifacts.py"
        self.script.parent.mkdir()
        shutil.copyfile(REPOSITORY / "scripts" / "client-artifacts.py", self.script)
        self.wrapper = self.script.parent / "fetch-deb.sh"
        shutil.copyfile(REPOSITORY / "scripts" / "fetch-deb.sh", self.wrapper)
        self.bin = self.root / "mock-bin"
        self.bin.mkdir()
        shutil.copyfile(REPOSITORY / "tests" / "fixtures" / "artifacts" / "curl", self.bin / "curl")
        (self.bin / "curl").chmod(0o755)
        self.sources = self.root / "fixture-sources"
        self.sources.mkdir()
        self.manifest = {
            "schema_version": 1,
            "release": {"version": "3.2.16", "revision": "r8362"},
            "base_image": "debian:trixie-slim@sha256:" + "a" * 64,
            "artifacts": {},
        }
        for arch, suffix in (("amd64", "0d182a"), ("arm64", "038591")):
            data = miniature_deb(arch)
            (self.sources / f"{arch}.deb").write_bytes(data)
            filename = f"FeiLian_Linux_{arch}_v3.2.16_r8362_{suffix}.deb"
            url = f"https://cdn.isealsuite.com/linux/{filename}"
            self.manifest["artifacts"][arch] = {
                "filename": filename, "url": url, "sha256": hashlib.sha256(data).hexdigest(),
                "deb_package": "com.volcengine.feilian", "deb_version": "3.2.16", "deb_architecture": arch,
                "verification": {"method": "maintainer-reviewed-tls", "reference": url, "approved": True},
            }
        self.lock = self.root / "config" / "client.lock.json"
        self.lock.parent.mkdir()
        self.write_manifest()
        self.log = self.root / "curl-arguments.jsonl"
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "MOCK_CURL_SOURCE_DIR": str(self.sources), "MOCK_CURL_LOG": str(self.log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def write_manifest(self, value=None) -> None:
        self.lock.write_text(json.dumps(self.manifest if value is None else value), encoding="utf-8")

    def cli(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [sys.executable, str(self.script), *args], cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        return result

    def cache(self, arch="amd64") -> Path:
        return self.root / "dist" / "3.2.16" / arch / "client.deb"

    def seed_legacy(self, arch="amd64") -> Path:
        target = self.root / "dist" / self.manifest["artifacts"][arch]["filename"]
        target.parent.mkdir(exist_ok=True)
        target.write_bytes((self.sources / f"{arch}.deb").read_bytes())
        return target

    def curl_calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_validate_and_export_contract_without_cache_or_network(self) -> None:
        result = json.loads(self.cli("validate", "--arch", "amd64").stdout)
        self.assertTrue(result["valid"])
        self.assertEqual(result["architectures"], ["amd64"])
        exported = json.loads(self.cli("export", "--arch", "arm64", "--format", "json").stdout)
        self.assertEqual(exported["CLIENT_VERSION"], "3.2.16")
        self.assertEqual(exported["CLIENT_REVISION"], "r8362")
        self.assertEqual(exported["CLIENT_DEB_PATH"], str(self.cache("arm64")))
        self.assertEqual(exported["CLIENT_DEB_SHA256"], self.manifest["artifacts"]["arm64"]["sha256"])
        self.assertEqual(exported["CLIENT_DEB_ARCHITECTURE"], "arm64")
        self.assertEqual(exported["BASE_IMAGE"], self.manifest["base_image"])
        all_arch = json.loads(self.cli("export", "--arch", "all").stdout)
        self.assertEqual(set(all_arch), {"amd64", "arm64"})
        self.assertFalse((self.root / "dist").exists())
        self.assertFalse(self.log.exists())

    def test_env_export_is_shell_quoted_and_rejects_all(self) -> None:
        result = self.cli("export", "--arch", "amd64", "--format", "env")
        values = {
            key: shlex.split(value)[0] for key, _, value in (line.partition("=") for line in result.stdout.splitlines())
        }
        self.assertEqual(values["CLIENT_DEB_PATH"], str(self.cache()))
        self.assertEqual(values["CLIENT_DEB_PACKAGE"], "com.volcengine.feilian")
        self.cli("export", "--arch", "all", "--format", "env", expected=2)

    def test_rejects_schema_typos_unreviewed_hashes_and_inconsistent_metadata(self) -> None:
        mutations = [
            ("schema_version", True), ("schema_version", 2), ("base_image", "debian:trixie-slim"),
        ]
        for key, value in mutations:
            manifest = copy.deepcopy(self.manifest)
            manifest[key] = value
            with self.subTest(key=key, value=value):
                self.write_manifest(manifest)
                self.cli("validate", expected=2)
        bad_artifacts = {
            "sha256": ("a" * 63, "a" * 65, "G" * 64, "A" * 64, None),
            "filename": ("../escape.deb", "FeiLian_Linux_arm64_v3.2.16_r8362_0d182a.deb", "x.deb"),
            "deb_package": ("other.package", None),
            "deb_version": ("3.2.17",), "deb_architecture": ("arm64", "all"),
        }
        for key, values in bad_artifacts.items():
            for value in values:
                manifest = copy.deepcopy(self.manifest)
                manifest["artifacts"]["amd64"][key] = value
                with self.subTest(key=key, value=value):
                    self.write_manifest(manifest)
                    self.cli("validate", expected=2)
        for field, value in (("approved", False), ("approved", 1), ("method", "vendor-signature"), ("reference", "https://example.invalid")):
            manifest = copy.deepcopy(self.manifest)
            manifest["artifacts"]["amd64"]["verification"][field] = value
            with self.subTest(field=field, value=value):
                self.write_manifest(manifest)
                self.cli("validate", expected=2)
        for target in ("root", "release", "artifact"):
            manifest = copy.deepcopy(self.manifest)
            obj = manifest if target == "root" else manifest["release"] if target == "release" else manifest["artifacts"]["amd64"]
            obj["typo"] = True
            self.write_manifest(manifest)
            self.cli("validate", expected=2)
        self.assertFalse(self.log.exists())

    def test_rejects_non_allowlisted_urls_and_traversal(self) -> None:
        good = self.manifest["artifacts"]["amd64"]["url"]
        urls = [
            good.replace("https:", "http:"), good.replace("cdn.isealsuite.com", "cdn.isealsuite.com.evil.invalid"),
            good.replace("cdn.isealsuite.com", "user:pass@cdn.isealsuite.com"),
            good.replace("cdn.isealsuite.com", "cdn.isealsuite.com:443"), good + "?x=y", good + "#fragment",
            good.replace("/linux/", "/linux/../linux/"), good.replace("/linux/", "/linux/%2e%2e/"),
            "file:///tmp/package.deb", None,
        ]
        for url in urls:
            manifest = copy.deepcopy(self.manifest)
            manifest["artifacts"]["amd64"]["url"] = url
            manifest["artifacts"]["amd64"]["verification"]["reference"] = url
            with self.subTest(url=url):
                self.write_manifest(manifest)
                self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertFalse(self.log.exists())

    def test_duplicate_json_keys_and_incomplete_other_arch_are_rejected(self) -> None:
        self.lock.write_text(self.lock.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        self.cli("validate", expected=2)
        manifest = copy.deepcopy(self.manifest)
        del manifest["artifacts"]["arm64"]["sha256"]
        self.write_manifest(manifest)
        self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertFalse(self.log.exists())

    def test_custom_manifest_path_is_honored(self) -> None:
        custom = self.root / "alternate.lock.json"
        custom.write_text(json.dumps(self.manifest))
        self.lock.write_text("not JSON")
        self.cli("validate", "--manifest", str(custom))
        self.cli("validate", expected=2)

    def test_offline_legacy_copy_never_moves_or_rewrites_original(self) -> None:
        original = self.seed_legacy()
        before = original.read_bytes()
        metadata = original.stat()
        result = json.loads(self.cli("fetch", "--arch", "amd64", "--offline").stdout)
        self.assertEqual(result["amd64"]["status"], "copied")
        self.assertEqual(self.cache().read_bytes(), before)
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(original.stat().st_ino, metadata.st_ino)
        self.assertEqual(original.stat().st_mtime_ns, metadata.st_mtime_ns)
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_cache_is_reverified_every_time_and_corruption_fails_closed(self) -> None:
        self.seed_legacy()
        self.cli("fetch", "--arch", "amd64", "--offline")
        first_stat = self.cache().stat()
        result = json.loads(self.cli("fetch", "--arch", "amd64", "--offline").stdout)
        self.assertEqual(result["amd64"]["status"], "cached")
        self.assertEqual(self.cache().stat().st_mtime_ns, first_stat.st_mtime_ns)
        self.cache().write_bytes(b"corrupt")
        result = self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual(self.cache().read_bytes(), b"corrupt")
        self.assertFalse(self.log.exists())

    def test_offline_miss_and_corrupt_legacy_do_not_download(self) -> None:
        self.cli("fetch", "--arch", "amd64", "--offline", expected=2)
        original = self.seed_legacy()
        original.write_bytes(b"invalid")
        self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertFalse(self.cache().exists())
        self.assertFalse(self.log.exists())

    def test_dry_run_has_no_network_or_filesystem_writes(self) -> None:
        result = json.loads(self.cli("fetch", "--arch", "all", "--dry-run").stdout)
        self.assertEqual({v["status"] for v in result.values()}, {"would-download"})
        self.assertFalse((self.root / "dist").exists())
        self.cli("fetch", "--arch", "amd64", "--offline", "--dry-run", expected=2)
        self.seed_legacy()
        result = json.loads(self.cli("fetch", "--arch", "amd64", "--offline", "--dry-run").stdout)
        self.assertEqual(result["amd64"]["status"], "would-copy")
        self.assertFalse(self.cache().parent.exists())
        self.assertFalse(self.log.exists())

    def test_mocked_download_is_verified_atomic_and_uses_only_locked_urls(self) -> None:
        result = json.loads(self.cli("fetch", "--arch", "all").stdout)
        self.assertEqual({v["status"] for v in result.values()}, {"downloaded"})
        for arch in ("amd64", "arm64"):
            self.assertEqual(self.cache(arch).read_bytes(), (self.sources / f"{arch}.deb").read_bytes())
            self.assertEqual(list(self.cache(arch).parent.glob("*.part")), [])
        calls = self.curl_calls()
        self.assertEqual(len(calls), 2)
        for arch, args in zip(("amd64", "arm64"), calls):
            self.assertEqual(args[args.index("--url") + 1], self.manifest["artifacts"][arch]["url"])
            self.assertEqual(args[args.index("--proto") + 1], "=https")
            self.assertEqual(args[args.index("--max-redirs") + 1], "0")
            temporary = Path(args[args.index("--output") + 1])
            self.assertEqual(temporary.parent, self.cache(arch).parent)
            self.assertTrue(temporary.name.endswith(".part"))
            self.assertNotEqual(temporary.name, "client.deb.part")

    def test_partial_downloads_have_unique_names_and_cleanup_only_their_own_parts(self) -> None:
        self.cache().parent.mkdir(parents=True)
        unrelated = self.cache().parent / ".client-unrelated.part"
        unrelated.write_bytes(b"unrelated transfer")
        self.env["MOCK_CURL_MODE"] = "partial"
        for _ in range(2):
            result = self.cli("fetch", "--arch", "amd64", expected=2)
            self.assertNotIn("PRIVATE_MARKER", result.stderr)
        calls = self.curl_calls()
        names = [args[args.index("--output") + 1] for args in calls]
        self.assertEqual(len(set(names)), 2)
        self.assertFalse(self.cache().exists())
        self.assertEqual(list(self.cache().parent.glob("*.part")), [unrelated])
        self.assertEqual(unrelated.read_bytes(), b"unrelated transfer")

    def test_interrupted_download_is_not_published_and_cleans_own_part(self) -> None:
        self.env["MOCK_CURL_MODE"] = "interrupt"
        result = self.cli("fetch", "--arch", "amd64", expected=130)
        self.assertIn("interrupted", result.stderr)
        self.assertFalse(self.cache().exists())
        self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_concurrent_fetches_use_distinct_parts_and_publish_identical_bytes(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: self.cli("fetch", "--arch", "amd64"), range(2)))
        self.assertEqual(len(results), 2)
        self.assertEqual(self.cache().read_bytes(), (self.sources / "amd64.deb").read_bytes())
        outputs = [args[args.index("--output") + 1] for args in self.curl_calls()]
        self.assertEqual(len(outputs), len(set(outputs)))
        self.assertGreaterEqual(len(outputs), 1)
        self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_legacy_symlink_is_rejected_even_if_content_matches_lock(self) -> None:
        legacy = self.root / "dist" / self.manifest["artifacts"]["amd64"]["filename"]
        legacy.parent.mkdir()
        legacy.symlink_to(self.sources / "amd64.deb")
        result = self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertIn("symlink", result.stderr)
        self.assertFalse(self.cache().exists())
        self.assertFalse(self.log.exists())

    def test_dry_run_rejects_corrupt_existing_cache(self) -> None:
        self.cache().parent.mkdir(parents=True)
        self.cache().write_bytes(b"corrupt")
        self.cli("fetch", "--arch", "amd64", "--dry-run", expected=2)
        self.assertFalse(self.log.exists())
        self.assertEqual(self.cache().read_bytes(), b"corrupt")

    def test_oversized_manifest_is_rejected_without_network(self) -> None:
        self.lock.write_text(" " * (1024 * 1024 + 1))
        self.cli("validate", expected=2)
        self.assertFalse(self.log.exists())

    def test_wrong_hash_download_is_not_published(self) -> None:
        self.manifest["artifacts"]["amd64"]["sha256"] = "b" * 64
        self.write_manifest()
        result = self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertFalse(self.cache().exists())
        self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_package_header_is_checked_even_when_digest_matches(self) -> None:
        wrong_packages = (
            miniature_deb("arm64"), miniature_deb(package="untrusted.package"),
            miniature_deb(version="3.2.17"), b"not a DEB archive",
        )
        for data in wrong_packages:
            with self.subTest(sha256=hashlib.sha256(data).hexdigest()):
                (self.sources / "amd64.deb").write_bytes(data)
                self.manifest["artifacts"]["amd64"]["sha256"] = hashlib.sha256(data).hexdigest()
                self.write_manifest()
                result = self.cli("fetch", "--arch", "amd64", expected=2)
                self.assertIn("DEB", result.stderr)
                self.assertFalse(self.cache().exists())
                self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_redirect_is_not_followed_or_published(self) -> None:
        self.env["MOCK_CURL_MODE"] = "redirect"
        result = self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertIn("HTTP 200", result.stderr)
        self.assertFalse(self.cache().exists())
        self.assertEqual(list(self.cache().parent.glob("*.part")), [])

    def test_cache_and_legacy_symlinks_are_rejected(self) -> None:
        outside = self.root / "outside.deb"
        outside.write_bytes((self.sources / "amd64.deb").read_bytes())
        self.cache().parent.mkdir(parents=True)
        self.cache().symlink_to(outside)
        result = self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertIn("symlink", result.stderr)
        self.assertFalse(self.log.exists())
        self.assertEqual(outside.read_bytes(), (self.sources / "amd64.deb").read_bytes())

    def test_symlinked_cache_parent_is_rejected_without_writes(self) -> None:
        outside = self.root / "outside-cache"
        outside.mkdir()
        (self.root / "dist").symlink_to(outside, target_is_directory=True)
        self.cli("fetch", "--arch", "amd64", expected=2)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(self.log.exists())

    def test_discovery_only_prints_unapproved_candidates_and_never_changes_lock(self) -> None:
        discovery = self.root / "page.js"
        urls = [artifact["url"] for artifact in self.manifest["artifacts"].values()]
        discovery.write_text(json.dumps({"linux": urls + [urls[0], "https://example.invalid/evil.deb"]}))
        self.env.update({"MOCK_CURL_MODE": "discovery", "MOCK_CURL_DISCOVERY": str(discovery)})
        before = self.lock.read_bytes()
        result = json.loads(self.cli("discover").stdout)
        self.assertEqual({entry["url"] for entry in result["candidates"]}, set(urls))
        self.assertTrue(all(entry["approved"] is False for entry in result["candidates"]))
        self.assertEqual(self.lock.read_bytes(), before)
        self.assertFalse((self.root / "dist").exists())
        discovery.write_text("no official URLs")
        self.cli("discover", expected=2)
        self.assertEqual(self.lock.read_bytes(), before)

    def test_shell_wrapper_is_thin_and_keeps_quoted_arguments(self) -> None:
        custom = self.root / "manifest with spaces.json"
        custom.write_text(json.dumps(self.manifest))
        result = subprocess.run(
            ["bash", str(self.wrapper), "--manifest", str(custom), "--arch", "amd64", "--dry-run"],
            cwd=self.root.parent, env=self.env, capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["amd64"]["status"], "would-download")
        self.assertFalse((self.root / "dist").exists())
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
