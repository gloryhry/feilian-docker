"""Offline supervisor tests: no containers, daemons, nft or network access."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("supervisor", ROOT / "runtime" / "supervisor.py")
sup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sup)


class FakeProcess:
    """Records lifecycle calls; never spawns anything."""

    instances: list["FakeProcess"] = []

    def __init__(self, name, argv, **kwargs):
        self.name, self.argv, self.kwargs = name, list(argv), kwargs
        self.pid, self.required, self.user = 0, kwargs.get("required", False), kwargs.get("user", "")
        self.starts = 0
        self.stops = 0
        self.bottom = False
        self.failures = 0
        self.next_try = 0.0
        self.pid_file = kwargs.get("pid_file")
        FakeProcess.instances.append(self)

    def alive(self):
        return bool(self.pid) and not self.bottom

    def start(self):
        self.starts += 1
        self.pid = 4242

    def poll(self):
        return None if self.alive() else (0 if self.starts else None)

    def stop(self, timeout=8.0):
        self.stops += 1
        self.pid = 0

    def _reap(self):
        self.pid = 0


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        FakeProcess.instances = []
        self.tmp = tempfile.TemporaryDirectory(prefix="supervisor-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        patches = [
            mock.patch.object(sup, "Process", FakeProcess),
            mock.patch.object(sup, "WEB_DIR", self.root / "web"),
            mock.patch.object(sup, "PROXY_DIR", self.root / "proxy"),
            mock.patch.object(sup, "LOG_DIR", self.root / "log"),
            mock.patch.object(sup, "SECRETS_DIR", self.root / "secrets"),
            mock.patch.object(sup.socket, "if_nametoindex", side_effect=self._ifindex),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def _ifindex(self, name):
        if name == "labvpn0":
            return 9
        raise OSError("no such interface")

    def supervisor(self, **env):
        base = {"FEILIAN_NETWORK_MODE": "bridge", "PROJECT_NAME": "t",
                "CORP_CIDRS": "10.60.0.0/16", "START_GUI": "0", "START_SERVICE": "0"}
        base.update(env)
        return sup.Supervisor(env=base, state_dir=self.state, runtime_dir=self.root)

    def write_vpn_status(self, state="READY", ready=True, ifindex=9, age=0.0):
        self.state.joinpath("status.json").write_text(json.dumps({
            "schema_version": 1, "state": state, "ready": ready,
            "updated_at": time.time() - age,
            "evidence": {"interface": "labvpn0", "vpn_ipv4": "10.99.0.2",
                         "dns_servers": ["10.91.0.53"]},
        }))

    def test_health_fails_closed_without_fresh_state(self):
        self.assertEqual(sup.health(self.state), 1)
        self.write_vpn_status()
        self.assertEqual(sup.health(self.state), 1)  # runtime.json still absent

    def test_health_requires_live_critical_process(self):
        sup._atomic_json(self.state / "runtime.json", {
            "schema_version": 1, "updated_at": time.time(),
            "processes": {"service": {"alive": False}}})
        self.assertEqual(sup.health(self.state), 1)
        sup._atomic_json(self.state / "runtime.json", {
            "schema_version": 1, "updated_at": time.time(),
            "processes": {"service": {"alive": True}}})
        self.assertEqual(sup.health(self.state), 0)

    def test_health_rejects_stale_state(self):
        sup._atomic_json(self.state / "runtime.json", {
            "schema_version": 1, "updated_at": time.time() - 600, "processes": {}})
        self.assertEqual(sup.health(self.state), 1)

    def test_host_mode_never_registers_managed_network_processes(self):
        supervisor = self.supervisor(FEILIAN_NETWORK_MODE="host")
        supervisor._bootstrap_plan()
        names = set(supervisor.procs)
        self.assertNotIn("controller", names)
        self.assertNotIn("dnsmasq", names)
        self.assertFalse(supervisor.managed)

    def test_data_plane_opens_only_on_ready_evidence_with_ifindex(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor._run_tool = mock.Mock(return_value=(0, json.dumps({"status": "READY"})))
        prepared = self.root / "proxy" / "proxy"
        prepared.mkdir(parents=True)
        (prepared / "microsocks.json").write_text(json.dumps({
            "argv": ["/usr/bin/microsocks", "-q", "-i", "127.0.0.1", "-p", "1080",
                     "-b", "10.99.0.2"]}))
        supervisor._await_listeners = lambda ports, timeout=15.0: True
        supervisor.open_data_plane({"evidence": {"interface": "labvpn0",
                                                 "interface_ifindex": 9,
                                                 "vpn_ipv4": ["10.99.0.2"],
                                                 "dns_servers": ["10.91.0.53"]}})
        self.assertEqual(supervisor.data_plane, "ready")
        self.assertEqual(supervisor.procs["microsocks"].user, "feilian-socks")
        self.assertEqual(supervisor.procs["privoxy"].user, "feilian-http")
        commands = [call.args[0] for call in supervisor._run_tool.call_args_list]
        self.assertEqual(commands[0][2], "apply")  # guard before config, then proxies
        self.assertEqual(commands[1][2], "prepare")

    def test_listener_timeout_never_reports_ready(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor._run_tool = mock.Mock(return_value=(0, json.dumps({"status": "READY"})))
        prepared = self.root / "proxy" / "proxy"
        prepared.mkdir(parents=True)
        (prepared / "microsocks.json").write_text(json.dumps({"argv": ["/usr/bin/microsocks"]}))
        supervisor._await_listeners = lambda ports, timeout=15.0: False
        supervisor.open_data_plane({"evidence": {"interface": "labvpn0", "interface_ifindex": 9,
                                                "vpn_ipv4": ["10.99.0.2"],
                                                "dns_servers": ["10.91.0.53"]}})
        self.assertEqual(supervisor.data_plane, "closed")
        self.assertIn("proxy_listen_timeout", supervisor.notes)

    def test_missing_ifindex_keeps_data_plane_closed(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor._run_tool = mock.Mock(return_value=(0, "{}"))
        supervisor.open_data_plane({"evidence": {"interface": "ghost0", "vpn_ipv4": ["10.99.0.2"]}})
        self.assertEqual(supervisor.data_plane, "closed")
        self.assertIn("data_plane_missing_ifindex", supervisor.notes)
        supervisor._run_tool.assert_not_called()

    def test_not_ready_status_keeps_plane_closed_and_loss_closes_it(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor._run_tool = mock.Mock(return_value=(0, "{}"))
        self.write_vpn_status(state="WAITING_AUTH", ready=False)
        supervisor.tick()
        self.assertEqual(supervisor.data_plane, "closed")
        supervisor.data_plane = "ready"
        supervisor.data_context = {"project": "t"}
        (self.root / "proxy").mkdir(exist_ok=True)
        (self.root / "proxy" / "context.json").write_text("{}")
        self.write_vpn_status(state="DISCONNECTED", ready=False)
        supervisor.tick()
        self.assertEqual(supervisor.data_plane, "closed")
        self.assertIn("readiness_lost", supervisor.notes)

    def test_stale_vpn_heartbeat_is_not_ready(self):
        supervisor = self.supervisor()
        self.write_vpn_status(age=600)
        self.assertIsNone(supervisor.vpn_status())

    def test_drain_stops_proxies_before_controller_and_honours_sigterm(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor.register("microsocks", ["/usr/bin/microsocks"], user="feilian-socks")
        supervisor.register("privoxy", ["privoxy"], user="feilian-http")
        supervisor._run_tool = mock.Mock(return_value=(0, "{}"))
        supervisor.data_plane = "ready"
        (self.root / "proxy").mkdir(exist_ok=True)
        (self.root / "proxy" / "context.json").write_text("{}")
        supervisor.drain()
        self.assertEqual(supervisor.procs["microsocks"].stops, 1)
        self.assertEqual(supervisor.procs["privoxy"].stops, 1)
        self.assertEqual(supervisor.procs["controller"].stops, 1)
        self.assertEqual(supervisor.data_plane, "closed")
        cleanup = [c.args[0] for c in supervisor._run_tool.call_args_list][-1]
        self.assertEqual(cleanup[2], "cleanup")

    def test_gui_keeps_electron_flags_in_argv(self):
        supervisor = self.supervisor(START_GUI="1", GUI_MODE="vnc")
        supervisor._bootstrap_plan()
        gui = supervisor.procs["gui"]
        # The client does not read an env var for these; without --no-sandbox
        # Electron refuses to start in a container that blocks user namespaces.
        self.assertIn("--no-sandbox", gui.argv)
        self.assertIn("--disable-gpu", gui.argv)
        self.assertNotIn("FEILIAN_GUI_ARGS", gui.kwargs.get("env_extra", {}))

    def test_crashing_child_backs_off_instead_of_restarting_every_tick(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        proc = supervisor.procs["nginx"]
        proc.start()
        proc.pid = 4242
        proc.poll = mock.Mock(return_value=1)      # started, then died rc=1
        proc._reap = mock.Mock(  # keep the fake pid bookkeeping simple
            side_effect=lambda: (setattr(proc, "pid", 0), setattr(proc, "handle", None)))
        supervisor.sync_processes()
        self.assertEqual(proc.failures, 1)
        self.assertGreater(proc.next_try, time.time() - 1)

    def test_dnsmasq_pid_file_is_published_for_the_dns_owner(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        dnsmasq = supervisor.procs["dnsmasq"]
        self.assertEqual(dnsmasq.pid_file, self.state / "dnsmasq.pid")
        self.assertIn("dns_forward.py", " ".join(dnsmasq.argv))
        # dnsmasq --no-daemon does not create a pid file itself; the supervisor is
        # the parent and must publish it or the DNS owner never activates.
        sup._atomic_text(self.state / "dnsmasq.pid", "4242\n", mode=0o600)
        self.assertEqual((self.state / "dnsmasq.pid").read_text(), "4242\n")
        self.assertEqual((self.state / "dnsmasq.pid").stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.state.glob("*.part")))

    def test_runtime_state_is_atomic_and_records_processes(self):
        supervisor = self.supervisor()
        supervisor._bootstrap_plan()
        supervisor.tick()
        state = json.loads((self.state / "runtime.json").read_text())
        self.assertEqual(state["schema_version"], 1)
        self.assertEqual(state["network_mode"], "bridge")
        self.assertTrue(state["managed_egress"])
        self.assertFalse(list(self.state.glob("*.part")))


if __name__ == "__main__":
    unittest.main()
