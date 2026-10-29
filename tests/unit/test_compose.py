"""Render Compose contracts only; do not connect to or start a Docker daemon."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI unavailable")
class ComposeContractTests(unittest.TestCase):
    def render(self, filename, extra=None):
        env = {**os.environ, "PROJECT_NAME": "compose-contract-test",
               "IMAGE_REF": "example.invalid/feilian:contract",
               "WEB_BIND": "127.0.0.1", "NOVNC_HOST_PORT": "7080",
               "NOVNC_INTERNAL_PORT": "6080", "STOP_TIMEOUT": "23",
               "WEB_TLS": "selfsigned", "WEB_AUTH": "1",
               "WEB_SOURCE_CIDRS": "192.0.2.0/24", "MACVLAN_IP": "192.0.2.9",
               **(extra or {})}
        result = subprocess.run(["docker", "compose", "--project-name", "compose-contract-test",
            "--env-file", "/dev/null", "-f", str(ROOT / filename), "config", "--format", "json"],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_common(self, config):
        service = config["services"]["feilian"]
        self.assertEqual(service["image"], "example.invalid/feilian:contract")
        self.assertNotIn("container_name", service)
        self.assertFalse(service.get("privileged", False))
        self.assertNotEqual(service.get("pid"), "host")
        self.assertIn("ALL", service["cap_drop"])
        self.assertNotIn("SYS_ADMIN", service["cap_add"])
        self.assertTrue(any("no-new-privileges" in item for item in service["security_opt"]))
        self.assertTrue(all(mount["type"] == "volume" for mount in service["volumes"]))
        self.assertFalse(any(mount["target"] == "/var/run/docker.sock" for mount in service["volumes"]))
        self.assertTrue({"/home/feilian", "/root", "/var/log/feilian"}.issubset(
            {mount["target"] for mount in service["volumes"]}))
        self.assertEqual(service["stop_grace_period"], "23s")
        self.assertNotIn("VNC_PASSWORD", service["environment"])
        return service

    def test_bridge_only_publishes_loopback_gui_and_owned_external_network(self):
        config = self.render("compose.yaml")
        service = self.assert_common(config)
        self.assertNotIn("network_mode", service)
        gui = next(port for port in service["ports"] if port["target"] == 6080)
        self.assertEqual(gui["host_ip"], "127.0.0.1")
        self.assertEqual(gui["published"], "7080")
        self.assertTrue(config["networks"]["feilian-net"]["external"])
        self.assertEqual(config["networks"]["feilian-net"]["name"], "compose-contract-test-net")

    def test_ipv6_loopback_uses_unambiguous_long_port_syntax(self):
        service = self.assert_common(self.render("compose.yaml", {"WEB_BIND": "::1"}))
        self.assertEqual(service["ports"][0]["host_ip"], "::1")
        self.assertEqual(service["ports"][0]["published"], "7080")

    def test_host_has_no_ports_or_managed_egress(self):
        service = self.assert_common(self.render("compose.host.yaml"))
        self.assertEqual(service["network_mode"], "host")
        self.assertNotIn("ports", service)
        self.assertNotIn("networks", service)
        env = service["environment"]
        self.assertEqual(env["NOVNC_BIND"], "127.0.0.1")
        self.assertEqual(str(env["NOVNC_PORT"]), "7080")
        for flag in ("PROXY_ENABLED", "GUARD_ENABLED", "GATEWAY_ENABLED"):
            self.assertEqual(str(env[flag]), "0")
        self.assertEqual(env["DNS_MODE"], "off")

    def test_macvlan_has_explicit_address_and_tls_acl(self):
        config = self.render("compose.macvlan.yaml")
        service = self.assert_common(config)
        self.assertNotIn("ports", service)
        self.assertEqual(service["networks"]["feilian-macvlan"]["ipv4_address"], "192.0.2.9")
        self.assertEqual(service["environment"]["WEB_TLS"], "selfsigned")
        self.assertEqual(service["environment"]["WEB_SOURCE_CIDRS"], "192.0.2.0/24")
        self.assertEqual(config["networks"]["feilian-macvlan"]["name"], "compose-contract-test-macvlan")


if __name__ == "__main__":
    unittest.main()
