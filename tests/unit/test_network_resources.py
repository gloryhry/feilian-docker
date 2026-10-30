"""Offline ownership tests: no real Docker, UFW, sudo or ip invocation."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("network_resources", ROOT / "scripts/network-resources.py")
nr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nr)


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.networks = {}
        self.ufw_status = "active"
        self.rules = []
        self.raw = "-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        self.counter = 0

    def call(self, args, *, check=True):
        self.calls.append(list(args))
        cmd = list(args)
        if cmd[:2] == ["sudo", "-n"]:
            cmd = cmd[2:]
        code, out, err = 0, "", ""
        if cmd[:3] == ["docker", "network", "inspect"]:
            current = self.networks.get(cmd[3])
            if current is None:
                code, err = 1, "Error: network not found"
            else:
                out = json.dumps([current])
        elif cmd[:3] == ["docker", "network", "create"]:
            name = cmd[-1]
            opts, labels = {}, {}
            for index, word in enumerate(cmd[:-1]):
                if word == "--label":
                    key, value = cmd[index + 1].split("=", 1)
                    labels[key] = value
                elif word == "--opt":
                    key, value = cmd[index + 1].split("=", 1)
                    opts[key] = value
            self.counter += 1
            driver = cmd[cmd.index("--driver") + 1]
            subnet = cmd[cmd.index("--subnet") + 1] if "--subnet" in cmd else "172.29.81.0/24"
            gateway = cmd[cmd.index("--gateway") + 1] if "--gateway" in cmd else "172.29.81.1"
            self.networks[name] = {"Id": f"network-id-{self.counter}", "Name": name,
                "Driver": driver, "Labels": labels, "Options": opts, "Containers": {},
                "IPAM": {"Config": [{"Subnet": subnet, "Gateway": gateway}]}}
            out = self.networks[name]["Id"]
        elif cmd[:3] == ["docker", "network", "rm"]:
            found = [name for name, data in self.networks.items() if data["Id"] == cmd[3]]
            if not found:
                raise AssertionError("attempted removal without resolved live ID")
            del self.networks[found[0]]
        elif cmd[:5] == ["ip", "-j", "-4", "route", "show"]:
            out = json.dumps([{"dev": "enp1s0", "metric": 100}])
        elif cmd[:4] == ["ip", "-j", "link", "show"]:
            out = json.dumps([{"ifname": "enp1s0"}, {"ifname": "Mihomo"}])
        elif cmd == ["ufw", "status"]:
            out = "Status: " + self.ufw_status
        elif cmd == ["ufw", "show", "added"]:
            out = "\n".join(shlex.join(["ufw", *rule]) for rule in self.rules)
        elif cmd == ["ufw", "show", "raw"]:
            out = self.raw
        elif cmd[:3] == ["ufw", "route", "allow"]:
            self.rules.append(cmd[1:])
        elif cmd[:4] == ["ufw", "--force", "route", "delete"]:
            rule = ["route", *cmd[4:]]
            self.rules.remove(rule)
        else:
            raise AssertionError(f"unexpected system call: {args!r}")
        result = subprocess.CompletedProcess(args, code, out, err)
        if check and code:
            raise nr.ResourceError(err)
        return result


class NetworkResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-network-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.runner = FakeRunner()
        self.resources = nr.Resources("test-project", self.runner, self.root)
        self.which = mock.patch.object(nr.shutil, "which", return_value="/usr/sbin/ufw")
        self.which.start()
        self.addCleanup(self.which.stop)
        self.uid = mock.patch.object(nr.os, "geteuid", return_value=1000)
        self.uid.start()
        self.addCleanup(self.uid.stop)

    def bridge(self):
        return self.resources.ensure_bridge()

    def mutations(self):
        return [c for c in self.runner.calls if c[:3] in (
            ["docker", "network", "create"], ["docker", "network", "rm"])
            or "allow" in c or "delete" in c]

    def test_ensure_bridge_is_owned_and_idempotent(self):
        first = self.bridge()
        self.assertEqual(first["action"], "created")
        self.assertEqual(self.resources.ensure_bridge()["action"], "reuse")
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.resources.path.stat().st_mode & 0o777, 0o600)
        loaded = nr.Resources("test-project", self.runner, self.root)
        self.assertEqual(len(loaded.ledger["networks"]), 1)

    def test_foreign_network_is_never_replaced(self):
        self.bridge()
        self.runner.networks["test-project-net"]["Labels"][nr.LABEL] = "someone-else"
        before = len(self.mutations())
        with self.assertRaises(nr.ResourceError):
            self.resources.ensure_bridge()
        self.assertEqual(len(self.mutations()), before)

    def test_changed_bridge_interface_is_rejected(self):
        self.bridge()
        self.runner.networks["test-project-net"]["Options"]["com.docker.network.bridge.name"] = "docker0"
        with self.assertRaises(nr.ResourceError):
            self.resources.bridge_details()

    def test_dry_run_writes_nothing(self):
        result = self.resources.ensure_bridge(dry_run=True)
        self.assertEqual(result["action"], "create")
        self.assertFalse(self.resources.path.exists())
        self.assertEqual(self.mutations(), [])

    def test_only_outbound_project_rule_is_applied(self):
        self.bridge()
        result = self.resources.apply()
        self.assertEqual(result["applied"], 1)
        rule = self.runner.rules[0]
        self.assertIn(self.resources.bridge, rule)
        self.assertIn("172.29.81.0/24", rule)
        self.assertEqual(rule[rule.index("out") + 2], "enp1s0")
        self.assertEqual(self.resources.apply()["applied"], 0)
        self.assertEqual(len(self.runner.rules), 1)
        self.assertFalse(any("flush" in c or "-F" in c for c in self.runner.calls))

    def test_preexisting_unowned_equivalent_is_reused_not_deleted(self):
        self.bridge()
        existing = ["route", "allow", "in", "on", self.resources.bridge, "out", "on",
                    "enp1s0", "from", "172.29.81.0/24", "comment", "unowned-marker"]
        self.runner.rules.append(existing)
        self.assertEqual(self.resources.apply()["applied"], 0)
        self.assertEqual(self.resources.ledger["ufw_rules"], [])
        self.resources.cleanup()
        self.assertEqual(self.runner.rules, [existing])

    def test_return_path_requires_stateful_forwarding(self):
        self.bridge()
        self.runner.raw = "-A ufw-before-forward -j DROP\n"
        with self.assertRaises(nr.ResourceError):
            self.resources.apply()
        self.assertEqual(self.runner.rules, [])
        self.assertEqual(self.resources.ledger["ufw_rules"], [])

    def test_ensure_access_creates_owned_network_with_exact_subnet(self):
        result = self.resources.ensure_access("192.168.77.0/24")
        self.assertEqual(result["action"], "created")
        self.assertEqual(result["subnet"], "192.168.77.0/24")
        self.assertEqual(self.resources.ensure_access("192.168.77.0/24")["action"], "reuse")

    def test_ensure_access_refuses_a_subnet_change(self):
        self.resources.ensure_access("192.168.77.0/24")
        with self.assertRaises(nr.ResourceError):
            self.resources.ensure_access("192.168.78.0/24")

    def test_ensure_access_rejects_foreign_network_and_default_subnet(self):
        self.resources.ensure_access("192.168.77.0/24")
        self.runner.networks["test-project-access"]["Labels"][nr.LABEL] = "someone-else"
        with self.assertRaises(nr.ResourceError):
            self.resources.ensure_access("192.168.77.0/24")
        for bad in ("", "0.0.0.0/0", "192.168.77.5/24", "fd00::/64"):
            with self.subTest(subnet=bad), self.assertRaises(nr.ResourceError):
                self.resources.ensure_access(bad)

    def test_cleanup_removes_the_access_network_by_its_own_name(self):
        self.resources.ensure_access("192.168.77.0/24")
        self.resources.cleanup()
        self.assertEqual(self.runner.networks, {})
        self.assertEqual([c for c in self.mutations() if "rm" in c], [["docker", "network", "rm",
                         self.runner.calls[-1][-1]]])

    def test_doctor_is_read_only_and_reports_transparent_proxy(self):
        self.bridge()
        before = len(self.mutations())
        result = self.resources.doctor()
        self.assertEqual(result["transparent_proxy_interfaces"], ["Mihomo"])
        self.assertEqual(len(self.mutations()), before)

    def test_cleanup_preserves_unowned_rule_and_removes_only_recorded_network(self):
        self.bridge()
        self.resources.apply()
        foreign = ["route", "allow", "from", "192.0.2.0/24", "comment", "foreign-marker"]
        self.runner.rules.append(foreign)
        result = self.resources.cleanup()
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(self.runner.rules, [foreign])
        self.assertEqual(self.runner.networks, {})
        self.assertEqual(self.resources.ledger["ufw_rules"], [])

    def test_cleanup_inactive_ufw_still_removes_persistent_rule(self):
        self.bridge()
        self.resources.apply()
        self.runner.ufw_status = "inactive"
        self.resources.cleanup()
        self.assertEqual(self.runner.rules, [])

    def test_cleanup_retain_changed_network_id(self):
        self.bridge()
        self.runner.networks["test-project-net"]["Id"] = "replacement-id"
        result = self.resources.cleanup()
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertIn("test-project-net", self.runner.networks)

    def test_cleanup_retain_network_in_use(self):
        self.bridge()
        self.runner.networks["test-project-net"]["Containers"] = {"foreign-container": {}}
        self.assertTrue(self.resources.cleanup()["conflicts"])
        self.assertIn("test-project-net", self.runner.networks)

    def test_macvlan_only_destroy_cannot_delete_bridge_or_ufw(self):
        self.bridge()
        self.resources.apply()
        self.resources.macvlan_create("enp1s0", "192.0.2.0/24", "192.0.2.1", "192.0.2.9")
        self.resources.cleanup(include_macvlan=True, macvlan_only=True)
        self.assertIn("test-project-net", self.runner.networks)
        self.assertNotIn("test-project-macvlan", self.runner.networks)
        self.assertEqual(len(self.runner.rules), 1)

    def test_macvlan_reuse_but_no_replacement(self):
        self.resources.macvlan_create("enp1s0", "192.0.2.0/24", "192.0.2.1", "192.0.2.9")
        result = self.resources.macvlan_create("enp1s0", "192.0.2.0/24", "192.0.2.1", "192.0.2.9")
        self.assertEqual(result["action"], "reuse")
        with self.assertRaises(nr.ResourceError):
            self.resources.macvlan_create("enp1s0", "192.0.2.0/24", "192.0.2.2", "192.0.2.9")
        self.assertEqual(len(self.mutations()), 1)

    def test_macvlan_rejects_network_broadcast_gateway_and_parent_injection(self):
        for parent, addr in (("x; echo bad", "192.0.2.9"), ("enp1s0", "192.0.2.0"),
                             ("enp1s0", "192.0.2.255"), ("enp1s0", "192.0.2.1")):
            with self.subTest(parent=parent, addr=addr), self.assertRaises(nr.ResourceError):
                self.resources.macvlan_create(parent, "192.0.2.0/24", "192.0.2.1", addr)
        self.assertEqual(self.mutations(), [])

    def test_symlink_ledger_path_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="feilian-outside-") as outside:
            (self.root / ".state").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(nr.ResourceError):
                nr.Resources("test-project", self.runner, self.root)
        self.assertEqual(self.runner.calls, [])

    def test_corrupt_or_foreign_ledger_is_not_overwritten(self):
        self.resources.save()
        self.resources.path.write_text('{"owner":"someone-else"}', encoding="utf-8")
        with self.assertRaises(nr.ResourceError):
            nr.Resources("test-project", self.runner, self.root)

    def test_no_privileged_rule_for_other_forward_chain(self):
        self.assertFalse(nr.has_stateful_forward("Chain FORWARD (policy DROP)\nACCEPT all ctstate RELATED,ESTABLISHED\n"))
        self.assertTrue(nr.has_stateful_forward("Chain ufw-before-forward (1 references)\n pkts bytes target prot\n 0 0 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED\nChain other (0 references)\n"))


if __name__ == "__main__":
    unittest.main()
