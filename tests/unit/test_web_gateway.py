"""Generate nginx text against disposable fixtures; never launch a server."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("feilian_web_gateway_test", ROOT / "runtime/web_gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-gateway-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "web"
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o750)
        for name, mode in (("web.htpasswd", 0o640), ("tls.crt", 0o644), ("tls.key", 0o600)):
            path = self.secrets / name
            path.write_text("synthetic-test-fixture-only\n")
            path.chmod(mode)

    def render(self, env=None):
        return gateway.render_config(env or {}, self.state, self.secrets, check_owner=False)

    def test_default_auth_applies_to_all_paths_and_websocket(self):
        text = self.render()
        self.assertIn('auth_basic "Feilian";', text)
        self.assertIn("auth_basic_user_file " + str(self.secrets / "web.htpasswd"), text)
        self.assertIn("upstream feilian_novnc { server unix:" + str(self.state / "novnc.sock"), text)
        self.assertIn("proxy_set_header Upgrade $http_upgrade", text)
        self.assertIn("proxy_set_header Connection $connection_upgrade", text)
        self.assertIn('proxy_set_header Authorization "";', text)
        self.assertIn("satisfy all;", text)
        self.assertEqual(text.count("location /"), 1)
        self.assertNotIn("auth_basic off", text)
        self.assertNotIn("127.0.0.1:5900", text)

    def test_no_access_logs_or_secret_contents(self):
        text = self.render()
        self.assertIn("access_log off;", text)
        self.assertNotIn("synthetic-test-fixture-only", text)
        self.assertNotIn("access.json", text)

    def test_lan_requires_auth_tls_and_source_acl(self):
        for env in ({"WEB_BIND": "0.0.0.0"},
                    {"WEB_BIND": "0.0.0.0", "WEB_TLS": "selfsigned"},
                    {"WEB_BIND": "0.0.0.0", "WEB_TLS": "selfsigned", "WEB_AUTH": "0", "WEB_SOURCE_CIDRS": "192.0.2.0/24"},
                    {"WEB_BIND": "0.0.0.0", "WEB_SOURCE_CIDRS": "192.0.2.0/24"}):
            with self.subTest(env=env), self.assertRaises(gateway.GatewayError):
                self.render(env)
        text = self.render({"WEB_BIND": "0.0.0.0", "WEB_TLS": "selfsigned", "WEB_SOURCE_CIDRS": "192.0.2.0/24"})
        self.assertIn("listen 0.0.0.0:6080 ssl;", text)
        self.assertIn("allow 192.0.2.0/24;", text)
        self.assertIn("deny all;", text)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", text)

    def test_macvlan_always_requires_lan_policy(self):
        with self.assertRaises(gateway.GatewayError):
            self.render({"FEILIAN_NETWORK_MODE": "macvlan"})
        self.assertIn(" ssl;", self.render({"FEILIAN_NETWORK_MODE": "macvlan", "WEB_TLS": "provided", "WEB_SOURCE_CIDRS": "192.0.2.1/32"}))

    def test_host_is_loopback_only_and_uses_host_port(self):
        text = self.render({"FEILIAN_NETWORK_MODE": "host", "NOVNC_HOST_PORT": "6091", "NOVNC_INTERNAL_PORT": "6080"})
        self.assertIn("listen 127.0.0.1:6091;", text)
        for key in ("NOVNC_BIND", "WEB_BIND"):
            with self.subTest(key=key), self.assertRaises(gateway.GatewayError):
                self.render({"FEILIAN_NETWORK_MODE": "host", key: "0.0.0.0", "WEB_TLS": "selfsigned", "WEB_SOURCE_CIDRS": "192.0.2.0/24"})

    def test_bridge_uses_internal_port(self):
        self.assertIn("listen 0.0.0.0:6082;", self.render({"NOVNC_HOST_PORT": "6090", "NOVNC_INTERNAL_PORT": "6082"}))

    def test_ipv6_literal_listener_is_bracketed(self):
        self.assertIn("listen [::1]:6080;", self.render({"FEILIAN_NETWORK_MODE": "host", "WEB_BIND": "::1", "NOVNC_BIND": "::1"}))

    def test_loopback_can_explicitly_disable_auth(self):
        (self.secrets / "web.htpasswd").unlink()
        text = self.render({"WEB_AUTH": "0"})
        self.assertNotIn("auth_basic", text)

    def test_missing_credentials_never_downgrade_auth_or_tls(self):
        for filename, env in (("web.htpasswd", {}), ("tls.crt", {"WEB_TLS": "selfsigned"}), ("tls.key", {"WEB_TLS": "provided"})):
            with self.subTest(filename=filename):
                path = self.secrets / filename
                previous = path.read_bytes()
                mode = stat.S_IMODE(path.stat().st_mode)
                path.unlink()
                with self.assertRaises(gateway.GatewayError):
                    self.render(env)
                path.write_bytes(previous)
                path.chmod(mode)

    def test_secret_permissions_and_link_rejection(self):
        key = self.secrets / "tls.key"
        key.chmod(0o644)
        with self.assertRaises(gateway.GatewayError):
            self.render({"WEB_TLS": "selfsigned"})
        auth = self.secrets / "web.htpasswd"
        auth.chmod(0o600)
        with self.assertRaises(gateway.GatewayError):
            self.render()
        auth.unlink()
        auth.symlink_to(key)
        with self.assertRaises(gateway.GatewayError):
            self.render()

    def test_injection_and_unsafe_source_lists_rejected(self):
        for env in ({"NOVNC_PORT": "6080;id"}, {"WEB_BIND": "localhost"},
                    {"WEB_AUTH": "yes"}, {"WEB_TLS": "insecure"},
                    {"WEB_SOURCE_CIDRS": "0.0.0.0/0"}, {"WEB_SOURCE_CIDRS": "192.0.2.1/24"},
                    {"WEB_SOURCE_CIDRS": "192.0.2.0/24;allow all"},
                    {"WEB_SOURCE_CIDRS": "192.0.2.0/24,192.0.2.0/24"}):
            with self.subTest(env=env), self.assertRaises(gateway.GatewayError):
                self.render(env)

    def test_prepare_atomic_modes_and_worker_temp_directories(self):
        target = gateway.prepare({}, self.state, self.secrets, check_owner=False)
        self.assertEqual(target, self.state / "nginx.conf")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o2750)
        self.assertEqual(stat.S_IMODE((self.state / "client-body").stat().st_mode), 0o770)
        self.assertEqual(stat.S_IMODE((self.state / "proxy-temp").stat().st_mode), 0o770)
        gateway.prepare({"NOVNC_INTERNAL_PORT": "6099"}, self.state, self.secrets, check_owner=False)
        self.assertIn(":6099;", target.read_text())
        self.assertEqual(list(self.state.glob(".nginx-*")), [])

    def test_validation_failure_writes_nothing(self):
        with self.assertRaises(gateway.GatewayError):
            gateway.prepare({"WEB_BIND": "0.0.0.0"}, self.state, self.secrets, check_owner=False)
        self.assertFalse(self.state.exists())

    def test_symlink_state_and_target_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(gateway.GatewayError):
            gateway.prepare({}, self.state, self.secrets, check_owner=False)
        self.assertFalse((outside / "nginx.conf").exists())
        self.state.unlink()
        self.state.mkdir()
        victim = outside / "victim"
        victim.write_text("untouched")
        (self.state / "nginx.conf").symlink_to(victim)
        with self.assertRaises(gateway.GatewayError):
            gateway.prepare({}, self.state, self.secrets, check_owner=False)
        self.assertEqual(victim.read_text(), "untouched")

    def test_controller_and_secrets_directory_must_not_be_reused(self):
        with self.assertRaises(gateway.GatewayError):
            gateway.prepare({}, "/run/feilian", self.secrets, check_owner=False)
        with self.assertRaises(gateway.GatewayError):
            gateway.prepare({}, self.secrets, self.secrets, check_owner=False)


if __name__ == "__main__":
    unittest.main()
