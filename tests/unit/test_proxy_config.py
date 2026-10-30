"""Pure proxy rendering/preparation tests: no proxies, DNS, routes or daemons."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from runtime import proxy_config as proxy

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "egress" / "ready.json"


class ProxyConfigTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(FIXTURE.read_text())
        temporary = tempfile.TemporaryDirectory(prefix="proxy-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "run" / "feilian-proxy"

    def context(self, **updates):
        raw = copy.deepcopy(self.raw)
        raw.update(updates)
        return proxy.normalize_context(raw)

    def render(self, **updates):
        return proxy.render_configs(self.context(**updates), self.state)

    def socks(self, result):
        return json.loads(result["files"]["microsocks.json"])

    def test_ready_uses_only_fixed_nonroot_users_and_current_vpn_address(self):
        result = self.render()
        spec = self.socks(result)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["daemon_uids"], {"socks": 1001, "http": 1002})
        self.assertEqual(spec["uid"], 1001)
        self.assertEqual(spec["user"], "feilian-socks")
        self.assertEqual(spec["bound_source_ipv4"], "10.99.0.2")
        self.assertEqual(spec["argv"][spec["argv"].index("-b") + 1], "10.99.0.2")
        self.assertNotIn("root", spec["argv"])
        self.assertNotIn("eth0", " ".join(spec["argv"]))
        self.assertEqual(spec["acl_owner"], "nft-guard")
        self.assertFalse(self.state.exists())

    def test_plain_http80_is_explicit_but_http_connect_is_only_configured_ports(self):
        result = self.render()
        self.assertIn(80, result["data_ports"])
        self.assertIn(443, result["data_ports"])
        self.assertIn("{+limit-connect{443}}", result["files"]["feilian.action"])
        self.assertNotIn("limit-connect{80", result["files"]["feilian.action"])
        config = result["files"]["privoxy.conf"]
        self.assertIn("forward-socks5t / 127.0.0.1:1080 .", config)
        self.assertNotIn("forward /", config)
        self.assertEqual(config.count("forward-socks5t"), 1)
        self.assertIn("enable-remote-toggle 0", config)
        result = self.render(connect_ports=[22, 443])
        self.assertIn("{+limit-connect{22,443}}", result["files"]["feilian.action"])
        self.assertIn(22, result["data_ports"])

    def test_default_source_acl_is_loopback_and_exact_captured_gateway(self):
        result = self.render()
        self.assertEqual(set(result["source_cidrs"]), {"127.0.0.1/32", "172.30.0.1/32"})
        config = result["files"]["privoxy.conf"]
        # Privoxy applies the LAST matching rule and resets denied clients, so the
        # catch-all deny must come first and the permits last.
        self.assertLess(config.index("deny-access 0.0.0.0/0"),
                        config.index("permit-access 172.30.0.1/32"))
        self.assertNotIn("permit-access 172.30.0.0/24", config)
        self.assertEqual(self.render(bridge_gateway="")["source_cidrs"], ["127.0.0.1/32"])

    def test_explicit_sources_do_not_implicitly_trust_whole_bridge(self):
        result = self.render(source_cidrs=["192.168.70.7/32"])
        self.assertEqual(set(result["source_cidrs"]), {"127.0.0.1/32", "192.168.70.7/32"})
        self.assertNotIn("permit-access 172.30.0.1/32", result["files"]["privoxy.conf"])

    def test_macvlan_without_shim_stays_loopback_even_with_lan_sources(self):
        result = self.render(network_mode="macvlan", source_cidrs=["192.168.70.0/24"])
        self.assertEqual(result["listen_ipv4"], "127.0.0.1")
        self.assertEqual(result["source_cidrs"], ["127.0.0.1/32"])
        self.assertEqual(self.socks(result)["listen_ipv4"], "127.0.0.1")
        result = self.render(network_mode="macvlan", macvlan_shim=True, source_cidrs=["192.168.70.7/32"])
        self.assertIn("192.168.70.7/32", result["source_cidrs"])

    def test_target_acl_is_packet_level_and_excludes_management_and_backend(self):
        result = self.render()
        # microsocks has no ACL language: enforcement is the nft guard's job, which
        # receives the computed data ports and denied targets with the same context.
        self.assertEqual(result["files"]["microsocks.json"].count("nft-guard"), 1)
        for target in ("127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "10.99.0.2/32"):
            self.assertIn(target, result["denied_targets"])
        private = self.render(corp_cidrs=["10.0.0.0/8"])
        # Do not blanket-deny RFC1918: these are normal enterprise destinations.
        self.assertNotIn("10.0.0.0/8", private["denied_targets"])
        self.assertIn("10.0.0.0/8", private["corp_cidrs"])

    def test_missing_ready_or_any_vpn_evidence_never_generates_runnable_files(self):
        for field in ("ready", "vpn_interface", "vpn_ipv4", "vpn_dns", "corp_cidrs"):
            raw = copy.deepcopy(self.raw)
            del raw[field]
            with self.subTest(field=field):
                result = proxy.render_configs(proxy.normalize_context(raw), self.state)
                self.assertEqual(result["status"], "CLOSED")
                self.assertFalse(result["effective_ready"])
                self.assertEqual(result["files"], {})
        self.assertEqual(self.render(proxy_enabled=False)["files"], {})

    def test_invalid_schema_fields_types_addresses_ports_and_interfaces_fail(self):
        cases = [
            {"schema_version": True}, {"schema_version": 2}, {"project": 'x";evil'}, {"ready": "1"},
            {"unknown": True}, {"vpn_interface": "eth0"}, {"vpn_interface": "lo"}, {"vpn_interface": "veth1"},
            {"vpn_interface": "tun0;evil"}, {"access_interface": "lo"}, {"vpn_ipv4": ["::1"]},
            {"vpn_ipv4": ["169.254.0.1"]}, {"vpn_dns": ["127.0.0.1"]}, {"corp_cidrs": ["::/0"]},
            {"source_cidrs": ["0.0.0.0/0"]}, {"corp_cidrs": ["10.60.1.1/16"]},
            {"source_cidrs": ["192.168.0.0/16", "192.168.0.1/32"]}, {"http_port": 80},
            {"http_port": 1080}, {"socks_port": True}, {"connect_ports": []}, {"connect_ports": [443, 443]},
            {"connect_ports": [53]}, {"connect_ports": [31055]}, {"gateway": {"unknown": 1}},
            {"gateway": {"mss": "auto"}}, {"gateway": {"enabled": "1"}},
        ]
        for update in cases:
            with self.subTest(update=update):
                with self.assertRaises(proxy.ProxyError):
                    self.context(**update)

    def gateway(self, **updates):
        value = {
            "enabled": True, "source_cidrs": ["192.168.70.7/32"], "access_subnet": "192.168.70.0/24",
            "gateway_ipv4": "192.168.70.2", "mss": "off",
        }
        value.update(updates)
        return value

    def test_gateway_sources_must_be_inside_access_and_not_overlap_corporate(self):
        self.context(gateway=self.gateway())
        for gateway in (
            self.gateway(source_cidrs=["192.168.71.0/24"]), self.gateway(gateway_ipv4="192.168.71.2"),
            self.gateway(gateway_ipv4="192.168.70.0"), self.gateway(mss=100), self.gateway(source_cidrs=[]),
        ):
            with self.subTest(gateway=gateway), self.assertRaises(proxy.ProxyError):
                self.context(gateway=gateway)
        with self.assertRaises(proxy.ProxyError):
            self.context(gateway=self.gateway(), corp_cidrs=["192.168.0.0/16"])
        for mode in ("off", "auto", 1200):
            self.context(gateway=self.gateway(mss=mode))

    def test_prepare_writes_nonsecret_readable_files_then_closed_removes_only_owned_configs(self):
        with patch("subprocess.run", side_effect=AssertionError("must not start daemons")):
            result = proxy.prepare(self.context(), self.state)
            self.assertEqual(result["status"], "READY")
            for name, path in result["paths"].items():
                self.assertEqual(Path(path), self.state / "proxy" / name)
                self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o644)
            unrelated = self.state / "proxy" / "keep.txt"
            unrelated.write_text("unrelated")
            closed = proxy.prepare(self.context(ready=False), self.state)
        self.assertEqual(closed["status"], "CLOSED")
        self.assertEqual(closed["paths"], {})
        self.assertTrue(unrelated.exists())
        for name in proxy.CONFIG_FILES:
            self.assertFalse((self.state / "proxy" / name).exists())
        self.assertEqual(json.loads((self.state / "proxy" / "status.json").read_text())["status"], "CLOSED")
        self.assertEqual(list((self.state / "proxy").glob("*.part")), [])

    def test_prepare_does_not_chmod_existing_private_state_parent(self):
        self.state.mkdir(parents=True, mode=0o750)
        before = stat.S_IMODE(self.state.stat().st_mode)
        proxy.prepare(self.context(), self.state)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), before)

    def test_other_project_or_unowned_configuration_is_never_overwritten(self):
        proxy.prepare(self.context(), self.state)
        path = self.state / "proxy" / "microsocks.json"
        before = path.read_bytes()
        with self.assertRaises(proxy.ProxyError):
            proxy.prepare(self.context(project="other-project"), self.state)
        self.assertEqual(path.read_bytes(), before)
        other_state = self.root / "unowned"
        (other_state / "proxy").mkdir(parents=True)
        (other_state / "proxy" / "privoxy.conf").write_text("keep")
        with self.assertRaises(proxy.ProxyError):
            proxy.prepare(self.context(), other_state)
        self.assertEqual((other_state / "proxy" / "privoxy.conf").read_text(), "keep")

    def test_symlinked_state_and_configuration_paths_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.state.parent.mkdir()
        self.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(proxy.ProxyError):
            proxy.prepare(self.context(), self.state)
        self.assertEqual(list(outside.iterdir()), [])
        safe = self.root / "safe"
        proxy.prepare(self.context(), safe)
        target = safe / "proxy" / "microsocks.json"
        self.assertEqual(target.resolve(), safe / "proxy" / "microsocks.json")
        target.unlink()
        target.symlink_to(outside / "do-not-write")
        with self.assertRaises(proxy.ProxyError):
            proxy.prepare(self.context(), safe)
        self.assertFalse((outside / "do-not-write").exists())

    def test_host_prepare_is_refused_before_any_directory_is_created(self):
        context = self.context(network_mode="host")
        self.assertEqual(proxy.render_configs(context, self.state)["status"], "CLOSED")
        with self.assertRaises(proxy.ProxyError):
            proxy.prepare(context, self.state)
        self.assertFalse(self.state.exists())

    def test_context_reader_rejects_duplicates_links_and_oversized_data(self):
        path = self.root / "context.json"
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(proxy.ProxyError):
            proxy.load_context(path)
        link = self.root / "context-link.json"
        link.symlink_to(FIXTURE)
        with self.assertRaises(proxy.ProxyError):
            proxy.load_context(link)
        path.write_text(" " * (proxy.MAX_CONTEXT + 1))
        with self.assertRaises(proxy.ProxyError):
            proxy.load_context(path)

    def test_cli_render_is_json_only_and_invalid_values_are_not_echoed(self):
        path = self.root / "context.json"
        path.write_text(json.dumps(self.raw))
        command = [sys.executable, str(ROOT / "runtime" / "proxy_config.py"), "render", "--context", str(path), "--state-dir", str(self.state)]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "READY")
        self.assertFalse(self.state.exists())
        bad = dict(self.raw, vpn_interface="PRIVATE_TEST_MARKER;bad")
        path.write_text(json.dumps(bad))
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("PRIVATE_TEST_MARKER", result.stderr)


if __name__ == "__main__":
    unittest.main()
