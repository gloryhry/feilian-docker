"""Mocked helper and Docker tests; never use real containers or credentials."""
from contextlib import redirect_stderr, redirect_stdout
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


volume = load("feilian_secrets_volume_test", ROOT / "runtime/secrets_volume.py")
sys.path.insert(0, str(ROOT / "scripts"))
try:
    cli = load("feilian_secrets_cli_test", ROOT / "scripts/secrets-cli.py")
finally:
    sys.path.pop(0)


class HelperRunner:
    def __init__(self):
        self.calls = []
        self.fail = False

    def call(self, args, input_data=None):
        self.calls.append((args, input_data))
        if self.fail:
            raise volume.SecretsError("synthetic tool failure")
        if args[0] == "htpasswd":
            return (args[-1] + ":$2y$12$" + "a" * 53 + "\n").encode()
        if args[0] == "x11vnc":
            Path(args[-1]).write_bytes(b"TESTONLY")
            return b"synthetic prompts must not reach logs"
        if args[0] == "openssl" and ("-pubkey" in args or "-pubout" in args):
            return b"SYNTHETIC_PUBLIC_KEY\n"
        if args[:2] == ["openssl", "req"]:
            Path(args[args.index("-out") + 1]).write_bytes(b"test certificate, not real\n")
            Path(args[args.index("-keyout") + 1]).write_bytes(b"test private key, not real\n")
        return b""


class VolumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-secrets-volume-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "volume"
        self.runner = HelperRunner()

    def manage(self, action="ensure", imports=None, owner="0123456789ab"):
        return volume.manage(action, self.directory, "testproject", owner,
                             imports=imports, runner=self.runner, check_owner=False)

    def source(self, name, value):
        path = self.root / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def test_generation_and_exact_modes(self):
        self.assertTrue(self.manage()["changed"])
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o750)
        for name, mode in volume.FILES.items():
            self.assertEqual(stat.S_IMODE((self.directory / name).stat().st_mode), mode)
        self.assertEqual(len((self.directory / "vnc.pass").read_bytes()), 8)
        self.assertTrue((self.directory / "web.htpasswd").read_bytes().startswith(b"feilian:$2y$"))
        self.assertEqual(list(self.directory.glob(".stage-*")), [])

    def test_passwords_only_enter_child_stdin(self):
        self.manage()
        backup = json.loads((self.directory / "access.json").read_text())
        for args, _ in self.runner.calls:
            self.assertNotIn(backup["web_password"], args)
            self.assertNotIn(backup["vnc_password"], args)
        web = next((args, data) for args, data in self.runner.calls if args[0] == "htpasswd")
        vnc = next((args, data) for args, data in self.runner.calls if args[0] == "x11vnc")
        self.assertIn(backup["web_password"].encode(), web[1])
        self.assertIn(backup["vnc_password"].encode(), vnc[1])

    def test_ensure_idempotent_without_new_tools_or_passwords(self):
        self.manage()
        previous = (self.directory / "access.json").read_bytes()
        count = len(self.runner.calls)
        self.assertFalse(self.manage()["changed"])
        self.assertEqual((self.directory / "access.json").read_bytes(), previous)
        self.assertEqual(len(self.runner.calls), count)

    def test_rotate_is_explicit_and_changes_credentials(self):
        self.manage()
        previous = (self.directory / "access.json").read_bytes()
        self.manage("rotate")
        self.assertNotEqual((self.directory / "access.json").read_bytes(), previous)

    def test_json_import_and_plaintext_vnc_source(self):
        source = self.source("credentials.json", json.dumps({"username": "fixture", "web_password": "SyntheticWebOnly123", "vnc_password": "T3stOnly"}).encode())
        self.manage("import", {"credential_file": source})
        backup = json.loads((self.directory / "access.json").read_text())
        self.assertEqual(backup["username"], "fixture")
        self.assertEqual(backup["web_password"], "SyntheticWebOnly123")
        self.assertEqual(backup["vnc_password"], "T3stOnly")

    def test_existing_import_source_fingerprint_is_idempotent(self):
        source = self.source("vnc", b"T3stOnly\n")
        self.manage(imports={"vnc_password_file": source})
        self.assertFalse(self.manage(imports={"vnc_password_file": source})["changed"])
        source.write_bytes(b"Changed1\n")
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"vnc_password_file": source})

    def test_new_source_requires_explicit_import_and_preserves_other_credentials(self):
        self.manage()
        previous = (self.directory / "access.json").read_bytes()
        source = self.source("ca", b"synthetic CA only\n")
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"probe_ca_file": source})
        self.manage("import", {"probe_ca_file": source})
        self.assertEqual((self.directory / "access.json").read_bytes(), previous)
        self.assertEqual((self.directory / "probe-ca.crt").read_bytes(), b"synthetic CA only\n")
        self.assertEqual(stat.S_IMODE((self.directory / "probe-ca.crt").stat().st_mode), 0o644)

    def test_bcrypt_import_does_not_invent_plaintext_backup(self):
        auth = self.source("web", b"fixture:$2y$12$" + b"a" * 53 + b"\n")
        self.manage(imports={"web_auth_file": auth})
        backup = json.loads((self.directory / "access.json").read_text())
        self.assertEqual(backup["username"], "fixture")
        self.assertIsNone(backup["web_password"])

    def test_foreign_or_unowned_volume_refused(self):
        self.manage()
        with self.assertRaises(volume.SecretsError):
            self.manage(owner="abcdef012345")
        (self.directory / ".owner.json").unlink()
        with self.assertRaises(volume.SecretsError):
            self.manage()

    def test_symlink_and_hardlinked_secret_inputs_refused(self):
        target = self.source("real", b"T3stOnly")
        linked = self.root / "linked"
        linked.symlink_to(target)
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"vnc_password_file": linked})
        linked.unlink()
        os.link(target, linked)
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"vnc_password_file": linked})

    def test_malformed_imports_and_overlong_vnc_fail_without_install(self):
        for raw in (b'{"username":"a","username":"b"}', b'{"unknown":"value"}',
                    b'{"username":"fixture","web_password":"short"}',
                    b'{"vnc_password":"longer-than-eight"}'):
            with self.subTest(raw=raw):
                source = self.source("credentials.json", raw)
                with self.assertRaises(volume.SecretsError):
                    self.manage("import", {"credential_file": source})
                self.assertFalse((self.directory / ".owner.json").exists())
                self.assertFalse((self.directory / "access.json").exists())

    def test_tool_failure_preserves_previous_credentials(self):
        self.manage()
        previous = (self.directory / "access.json").read_bytes()
        self.runner.fail = True
        with self.assertRaises(volume.SecretsError):
            self.manage("rotate")
        self.assertEqual((self.directory / "access.json").read_bytes(), previous)
        self.assertEqual(list(self.directory.glob(".stage-*")), [])

    def test_secret_permissions_not_silently_repaired(self):
        self.manage()
        (self.directory / "tls.key").chmod(0o644)
        with self.assertRaises(volume.SecretsError):
            self.manage()

    def test_import_requires_source_and_tls_pair(self):
        with self.assertRaises(volume.SecretsError):
            self.manage("import")
        cert = self.source("cert", b"test cert")
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"tls_cert_file": cert})

    def test_directory_permissions_and_concurrent_writer_are_rejected(self):
        self.manage()
        self.directory.chmod(0o777)
        with self.assertRaises(volume.SecretsError):
            self.manage()
        self.directory.chmod(0o750)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            volume.fcntl.flock(descriptor, volume.fcntl.LOCK_EX | volume.fcntl.LOCK_NB)
            with self.assertRaises(volume.SecretsError):
                self.manage("rotate")
        finally:
            os.close(descriptor)

    def test_imported_tls_public_keys_must_match(self):
        cert = self.source("cert.pem", b"synthetic certificate")
        key = self.source("key.pem", b"synthetic private key")
        original = self.runner.call
        def mismatched(args, input_data=None):
            if "-pubout" in args:
                return b"DIFFERENT_SYNTHETIC_KEY"
            return original(args, input_data)
        self.runner.call = mismatched
        with self.assertRaises(volume.SecretsError):
            self.manage(imports={"tls_cert_file": cert, "tls_key_file": key})
        self.assertFalse((self.directory / ".owner.json").exists())

    def test_stdin_envelope_limits_duplicates_unknown_and_invalid_encoding(self):
        valid = json.dumps({"schema_version": 1, "imports": {"vnc_password_file": base64.b64encode(b"T3stOnly").decode()}}).encode()
        self.assertEqual(volume.decode_stdin(valid), {"vnc_password_file": b"T3stOnly"})
        for raw in (b"x" * 600001, b'{}', b'{"schema_version":true,"imports":{}}',
                    b'{"schema_version":1,"imports":{},"imports":{}}',
                    b'{"schema_version":1,"imports":{"unknown":"YQ=="}}',
                    b'{"schema_version":1,"imports":{"vnc_password_file":"***"}}',
                    json.dumps({"schema_version": 1, "imports": {"vnc_password_file": base64.b64encode(b"x" * 65537).decode()}}).encode()):
            with self.subTest(length=len(raw)), self.assertRaises(volume.SecretsError):
                volume.decode_stdin(raw)
        result = volume.manage("ensure", self.directory, "testproject", "0123456789ab", runner=self.runner,
                               check_owner=False, import_data=volume.decode_stdin(valid))
        self.assertTrue(result["changed"])

    def test_stdin_helper_cli_does_not_emit_envelope(self):
        raw = json.dumps({"schema_version": 1, "imports": {"vnc_password_file": base64.b64encode(b"T3stOnly").decode()}}).encode()
        stream = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdin", stream), mock.patch.object(volume, "manage", return_value={}) as managed, redirect_stdout(stdout):
            self.assertEqual(volume.main(["ensure", "--project", "testproject", "--owner", "0123456789ab", "--stdin-json"]), 0)
        self.assertEqual(managed.call_args.kwargs["import_data"], {"vnc_password_file": b"T3stOnly"})
        self.assertEqual(stdout.getvalue(), "feilian secrets: prepared\n")

    def test_helper_main_never_emits_passwords(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(volume, "manage", return_value={"changed": True}), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(volume.main(["ensure", "--project", "testproject", "--owner", "0123456789ab"]), 0)
        self.assertEqual(stdout.getvalue(), "feilian secrets: prepared\n")
        self.assertEqual(stderr.getvalue(), "")


class DockerRunner:
    def __init__(self):
        self.calls = []
        self.manager = None
        self.exists = False
        self.foreign = False
        self.helper_exit = "0"
        self.foreign_helper = False
        self.inputs = []

    def call(self, args, check=True, input_data=None):
        self.calls.append(args)
        if input_data is not None:
            self.inputs.append((args, input_data))
        manager = self.manager
        code, output = 0, ""
        if args[:3] == ["docker", "volume", "inspect"]:
            if not self.exists:
                code = 1
            else:
                output = json.dumps([{"Name": manager.volume, "Driver": "local", "Labels": {
                    "io.feilian.owner": "foreign" if self.foreign else manager.owner,
                    "io.feilian.project": manager.project, "io.feilian.role": "secrets"}}])
        elif args[:3] == ["docker", "volume", "create"]:
            self.exists = True
        elif args[:2] == ["docker", "create"]:
            output = "a" * 64 + "\n"
        elif args[:2] == ["docker", "start"]:
            output = "synthetic helper output is never forwarded"
        elif args[:2] == ["docker", "inspect"]:
            output = self.helper_exit
        elif args[:2] == ["docker", "cp"]:
            Path(args[-1]).write_text('{"synthetic_backup":"not real credentials"}\n')
        elif args[:3] == ["docker", "container", "inspect"]:
            output = json.dumps({"io.feilian.owner": "foreign" if self.foreign_helper else manager.owner,
                                 "io.feilian.project": manager.project, "io.feilian.role": "secrets-helper"})
        if check and code:
            raise cli.SecretsError("synthetic docker failure")
        return SimpleNamespace(returncode=code, stdout=output, stderr="not forwarded")


class HostSecretsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-secrets-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = dict(cli.config.DEFAULTS, IMAGE_REF="test:wrapper")
        self.runner = DockerRunner()
        self.manager = cli.Manager(self.settings, root=self.root, runner=self.runner)
        self.runner.manager = self.manager

    def test_owned_volume_network_none_helper_and_private_cp_backup(self):
        result = self.manager.perform("ensure")
        self.assertEqual(result["volume"], "feilian-secrets")
        commands = self.runner.calls
        create = next(args for args in commands if args[:2] == ["docker", "create"])
        self.assertEqual(create[create.index("--network") + 1], "none")
        self.assertEqual(create[create.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", create)
        self.assertIn("io.feilian.owner=" + self.manager.owner, create)
        self.assertIn("/opt/feilian/runtime/secrets_volume.py", create)
        self.assertTrue(any(args[:2] == ["docker", "cp"] for args in commands))
        self.assertTrue(any(args[:2] == ["docker", "rm"] for args in commands))
        self.assertEqual(stat.S_IMODE(self.manager.backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.manager.backup.parent.stat().st_mode), 0o700)
        self.assertFalse((self.root / "docker.env").exists())

    def test_foreign_volume_refused_before_helper(self):
        self.runner.exists, self.runner.foreign = True, True
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.assertFalse(any(args[:2] in (["docker", "create"], ["docker", "rm"]) for args in self.runner.calls))

    def test_helper_failure_never_exports_backup(self):
        self.runner.helper_exit = "2"
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.assertFalse(self.manager.backup.exists())
        self.assertFalse(any(args[:2] == ["docker", "cp"] for args in self.runner.calls))
        self.assertTrue(any(args[:2] == ["docker", "rm"] for args in self.runner.calls))

    def test_foreign_helper_cleanup_is_refused(self):
        self.runner.foreign_helper = True
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.assertFalse(any(args[:2] == ["docker", "rm"] for args in self.runner.calls))

    def test_dry_run_never_calls_docker(self):
        result = self.manager.perform("ensure", dry_run=True)
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(result["volume"], "feilian-secrets")

    def test_private_file_permissions_before_mount(self):
        source = self.root / "vnc-password"
        source.write_text("T3stOnly")
        source.chmod(0o644)
        self.settings["VNC_PASSWORD_FILE"] = str(source)
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.assertEqual(self.runner.calls, [])
        source.chmod(0o600)
        command = self.manager.perform("ensure", dry_run=True)["helper_command"]
        self.assertIn("--stdin-json", command)
        self.assertIn("--interactive", command)
        self.assertFalse(any("type=bind" in word for word in command))
        self.assertNotIn("DAC_READ_SEARCH", command)
        self.assertNotIn(str(source), command)
        self.assertNotIn("T3stOnly", command)
        self.manager.perform("ensure")
        self.assertEqual(len(self.runner.inputs), 1)
        args, raw = self.runner.inputs[0]
        self.assertEqual(args[:4], ["docker", "start", "--attach", "--interactive"])
        self.assertEqual(volume.decode_stdin(raw.encode())["vnc_password_file"], b"T3stOnly")

    def test_probe_ca_source_maps_to_normalized_runtime_file(self):
        source = self.root / "ca.crt"
        source.write_text("synthetic CA")
        self.settings["VPN_PROBE_CA_FILE"] = str(source)
        command = self.manager.perform("ensure", dry_run=True)["helper_command"]
        self.assertIn("--stdin-json", command)
        self.assertNotIn(str(source), command)
        self.manager.perform("ensure")
        data = volume.decode_stdin(self.runner.inputs[0][1].encode())
        self.assertEqual(data["probe_ca_file"], b"synthetic CA")

    def test_symlink_source_and_backup_rejected(self):
        target = self.root / "outside"
        target.write_text("untouched")
        (self.root / "link").symlink_to(target)
        self.settings["VNC_PASSWORD_FILE"] = str(self.root / "link")
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.settings["VNC_PASSWORD_FILE"] = ""
        self.manager.backup.parent.mkdir(parents=True)
        self.manager.backup.symlink_to(target)
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("ensure")
        self.assertEqual(target.read_text(), "untouched")

    def test_import_requires_explicit_source(self):
        with self.assertRaises(cli.SecretsError):
            self.manager.perform("import")
        self.assertEqual(self.runner.calls, [])

    def test_main_output_only_names_private_backup_path(self):
        manager = mock.Mock()
        manager.perform.return_value = {"backup": "/test/.state/feilian/access.json"}
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.config, "load_config", return_value=self.settings), mock.patch.object(cli, "Manager", return_value=manager), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cli.main(["ensure"]), 0)
        self.assertIn("/test/.state/feilian/access.json", stdout.getvalue())
        self.assertNotIn("synthetic helper output", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
