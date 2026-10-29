"""Offline VPN state/protocol tests; all IO lives in tmp or injected stubs."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request

from runtime import vpn_state as vpn


class Clock:
    def __init__(self):
        self.now = 1700000000.0
        self.elapsed = 100.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.elapsed

    def advance(self, seconds):
        self.now += seconds
        self.elapsed += seconds


class Runner:
    def __init__(self):
        self.calls = []
        self.route_devices = {}
        self.device = "corp-link0"
        self.flags = ["UP", "LOWER_UP", "POINTOPOINT"]
        self.kind = "tun"
        self.operstate = "UNKNOWN"
        self.addresses = [{"family": "inet", "local": "10.20.0.2", "scope": "global"}]
        self.fail = False
        self.source = "10.20.0.2"

    def run(self, args, timeout):
        self.calls.append((args, timeout))
        assert args[:2] == ["ip", "-j"]
        if self.fail:
            return SimpleNamespace(returncode=1, stdout=b"")
        if args[2:4] == ["route", "get"]:
            value = [{"dev": self.route_devices.get(args[4], self.device), "prefsrc": self.source}]
        elif args[2:4] == ["link", "show"]:
            value = [{"ifname": self.device, "flags": self.flags, "operstate": self.operstate,
                      "linkinfo": {"info_kind": self.kind}}]
        elif args[2:4] == ["address", "show"]:
            value = [{"ifname": self.device, "addr_info": self.addresses}]
        else:
            raise AssertionError("Unexpected command: " + repr(args))
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())


class Resolver:
    def __init__(self):
        self.calls = []
        self.answers = ("10.20.30.40",)
        self.failure = None

    def resolve(self, name, servers, timeout):
        self.calls.append((name, servers, timeout))
        if self.failure:
            raise vpn.ProbeError(self.failure)
        return self.answers


class HTTP:
    def __init__(self):
        self.calls = []
        self.status = 200
        self.failure = None

    def probe(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failure:
            raise vpn.ProbeError(self.failure)
        return self.status


class DNS:
    def __init__(self):
        self.calls = []
        self.active = True
        self.failure = False
        self.restored = 0
        self.closed = 0

    def apply(self, connected, servers, domains, mode):
        self.calls.append((connected, servers, domains, mode))
        if self.failure:
            raise vpn.DNSError("do_not_log_secret_payload")
        return {"managed": mode != "off", "active": self.active,
                "mode": ("split" if domains else "full") if mode == "auto" else mode}

    def restore(self):
        self.restored += 1

    def close(self):
        self.closed += 1


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = Clock()
        self.state_dir = self.root / "state"
        self.store = vpn.StateStore(self.state_dir, self.clock)
        self.runner = Runner()
        self.resolver = Resolver()
        self.http = HTTP()
        self.dns = DNS()
        self.env = {"FEILIAN_NETWORK_MODE": "bridge", "CORP_DOMAINS": "corp.test",
                    "CORP_CIDRS": "10.0.0.0/8", "DNS_MODE": "split", "VPN_DNS_SOURCE": "manual",
                    "VPN_DNS": "10.20.0.53,10.20.0.54", "VPN_IFACE": "auto",
                    "VPN_PROBE_DNS_NAME": "health.corp.test", "VPN_PROBE_URL": "https://health.corp.test/health"}

    def tearDown(self):
        self.tmp.cleanup()

    def controller(self, env=None, **kwargs):
        return vpn.Controller(vpn.Config.from_env(env if env is not None else self.env), self.store,
                              self.runner, self.clock, self.resolver, self.http, self.dns, **kwargs)

    def file_env(self, content=b'{"DNS":["10.20.0.53"]}', age=0):
        path = self.root / "vpn.conf"
        path.write_bytes(content)
        os.utime(path, (self.clock.now - age, self.clock.now - age))
        return dict(self.env, VPN_DNS_SOURCE="file", VPN_CONFIG_FILE=str(path))

    def test_no_corporate_targets_is_live_unconfigured_without_network_probe(self):
        env = dict(self.env, CORP_DOMAINS="", CORP_CIDRS="", VPN_PROBE_DNS_NAME="", VPN_PROBE_URL="", DNS_MODE="auto")
        snapshot = self.controller(env).once()
        self.assertEqual(snapshot["state"], "UNCONFIGURED")
        self.assertTrue(snapshot["live"])
        self.assertFalse(snapshot["ready"])
        self.assertFalse(self.runner.calls or self.resolver.calls or self.http.calls)
        self.assertEqual(self.dns.calls[0][0], False)

    def test_invalid_configuration_can_remain_live_for_gui(self):
        controller = vpn.Controller(None, self.store, clock=self.clock, config_error="invalid_network_mode")
        snapshot = controller.once()
        self.assertEqual(snapshot["state"], "UNCONFIGURED")
        self.assertTrue(snapshot["live"])
        self.assertEqual(snapshot["reason"], "invalid_network_mode")

    def test_two_consecutive_successes_then_any_failure_immediately_withdraws(self):
        controller = self.controller()
        first = controller.once()
        self.assertEqual(first["state"], "VALIDATING")
        self.assertFalse(first["ready"])
        self.clock.advance(5)
        second = controller.once()
        self.assertEqual(second["state"], "READY")
        self.assertTrue(second["ready"])
        self.assertEqual(second["evidence"]["success_count"], 2)
        self.assertEqual(second["evidence"]["interface"], "corp-link0")
        self.assertEqual(self.http.calls[0][0][1:3], ("10.20.30.40", "10.20.0.2"))
        self.http.failure = "https_verification_failed"
        self.clock.advance(5)
        failed = controller.once()
        self.assertEqual(failed["state"], "DEGRADED")
        self.assertFalse(failed["ready"])
        self.assertEqual(failed["evidence"]["success_count"], 0)
        self.assertFalse(self.dns.calls[-1][0])
        self.http.failure = None
        self.assertEqual(controller.once()["state"], "VALIDATING")
        self.assertTrue(controller.once()["ready"])

    def test_once_reloads_only_fresh_matching_success_counter(self):
        self.assertEqual(self.controller().once()["state"], "VALIDATING")
        self.assertTrue(self.controller().once()["ready"])
        self.clock.advance(21)
        self.assertEqual(self.controller().once()["state"], "VALIDATING")
        changed = dict(self.env, VPN_PROBE_URL="https://health.corp.test/different")
        self.assertEqual(self.controller(changed).once()["state"], "VALIDATING")

    def test_missing_vpn_file_waits_authentication_not_dead_or_ready(self):
        env = dict(self.env, VPN_DNS_SOURCE="file", VPN_CONFIG_FILE=str(self.root / "absent-vpn.conf"))
        snapshot = self.controller(env).once()
        self.assertEqual(snapshot["state"], "WAITING_AUTH")
        self.assertEqual(snapshot["reason"], "vpn_config_missing")
        self.assertTrue(snapshot["live"])
        self.assertFalse(self.runner.calls)

    def test_malformed_null_oversized_duplicate_or_wrong_typed_json_never_ready(self):
        values = (b"null", b"{", b"[]", b'{"DNS":null}', b'{"DNS":"10.0.0.53"}',
                  b'{"DNS":[null]}', b'{"DNS":[]}', b'{"DNS":["127.0.0.1"]}',
                  b'{"DNS":[],"DNS":["10.20.0.53"]}', b" " * 65537,
                  json.dumps({"DNS": ["10.20.0.53"] * 9}).encode(),
                  json.dumps({"DNS": ["10.20.0.53"], **{str(i): 1 for i in range(65)}}).encode())
        for raw in values:
            with self.subTest(raw=raw[:80]):
                snapshot = self.controller(self.file_env(raw)).once()
                self.assertFalse(snapshot["ready"])
                self.assertEqual(snapshot["reason"], "vpn_config_invalid")
        self.assertFalse(self.http.calls)

    def test_stale_candidate_still_requires_all_fresh_probes_and_can_be_ready(self):
        controller = self.controller(self.file_env(age=3600))
        self.assertEqual(controller.once()["state"], "VALIDATING")
        snapshot = controller.once()
        self.assertTrue(snapshot["ready"])
        self.assertTrue(snapshot["evidence"]["dns_config_stale"])
        self.assertEqual(snapshot["evidence"]["dns_age_seconds"], 3600)
        self.assertEqual(len(self.resolver.calls), 2)
        self.assertEqual(len(self.http.calls), 2)

    def test_old_file_alone_with_no_tunnel_or_failed_https_never_ready(self):
        env = self.file_env(age=3600)
        self.runner.fail = True
        snapshot = self.controller(env).once()
        self.assertFalse(snapshot["ready"])
        self.assertFalse(self.http.calls)
        self.runner.fail = False
        self.http.failure = "https_verification_failed"
        snapshot = self.controller(env).once()
        self.assertFalse(snapshot["ready"])
        self.assertTrue(snapshot["evidence"]["dns_config_stale"])

    def test_future_timestamp_and_vpn_file_symlink_fail_closed(self):
        env = self.file_env(age=-60)
        self.assertEqual(self.controller(env).once()["reason"], "vpn_config_timestamp_invalid")
        target = self.root / "other"
        target.write_text('{"DNS":["10.20.0.53"]}')
        path = Path(env["VPN_CONFIG_FILE"])
        path.unlink()
        path.symlink_to(target)
        self.assertEqual(self.controller(env).once()["reason"], "vpn_config_invalid")

    def test_actual_target_route_not_tun_name_selects_interface(self):
        self.assertEqual(self.controller().once()["evidence"]["interface"], "corp-link0")
        self.runner.route_devices["10.20.30.40"] = "eth0"
        self.assertEqual(self.controller().once()["reason"], "target_not_routed_via_vpn")
        self.assertEqual(len(self.http.calls), 1)

    def test_tun_looking_non_tunnel_interface_is_not_enough(self):
        self.runner.device = "tun0"
        self.runner.flags = ["UP", "LOWER_UP"]
        self.runner.kind = "veth"
        self.assertEqual(self.controller().once()["reason"], "vpn_interface_not_tunnel")
        self.assertFalse(self.http.calls)

    def test_explicit_interface_must_match_actual_routes(self):
        snapshot = self.controller(dict(self.env, VPN_IFACE="tun9")).once()
        self.assertEqual(snapshot["reason"], "target_not_routed_via_vpn")

    def test_down_or_unaddressed_interface_never_ready(self):
        self.runner.operstate = "DOWN"
        self.assertEqual(self.controller().once()["reason"], "vpn_interface_inactive")
        self.runner.operstate = "UP"
        self.runner.addresses = []
        self.assertEqual(self.controller().once()["reason"], "vpn_interface_no_ipv4")

    def test_every_dns_server_must_route_over_the_same_vpn(self):
        self.runner.route_devices["10.20.0.54"] = "eth0"
        snapshot = self.controller().once()
        self.assertEqual(snapshot["reason"], "dns_not_routed_via_vpn")
        self.assertFalse(self.resolver.calls)

    def test_dns_query_failure_not_replaced_by_public_resolver(self):
        self.resolver.failure = "enterprise_dns_query_failed"
        snapshot = self.controller().once()
        self.assertEqual(snapshot["reason"], "enterprise_dns_query_failed")
        self.assertEqual(self.resolver.calls[0][1], ("10.20.0.53", "10.20.0.54"))
        self.assertFalse(self.http.calls)

    def test_public_200_and_ipv6_only_answer_never_count_as_corporate(self):
        for answer in (("8.8.8.8",), ("::1",), ("2001:db8::2",), ("127.0.0.1",)):
            with self.subTest(answer=answer):
                self.resolver.answers = answer
                self.assertFalse(self.controller().once()["ready"])
        self.assertFalse(self.http.calls)

    def test_without_cidrs_only_internal_ipv4_answers_qualify(self):
        env = dict(self.env, CORP_CIDRS="")
        self.assertEqual(self.controller(env).once()["state"], "VALIDATING")
        self.resolver.answers = ("8.8.8.8",)
        self.assertEqual(self.controller(env).once()["reason"], "probe_target_not_corporate")

    def test_redirect_and_wrong_http_status_never_succeed(self):
        for status in (302, 301, 401, 204):
            self.http.status = status
            with self.subTest(status=status):
                self.assertEqual(self.controller().once()["reason"], "https_unexpected_status")

    def test_route_source_must_belong_to_vpn_interface(self):
        self.runner.source = "192.168.1.2"
        self.assertEqual(self.controller().once()["reason"], "vpn_source_address_mismatch")

    def test_dns_daemon_must_be_running_before_managed_readiness(self):
        self.dns.active = False
        controller = self.controller()
        self.assertEqual(controller.once()["reason"], "dnsmasq_not_running")
        self.assertFalse(controller.once()["ready"])
        self.assertEqual(len(self.http.calls), 2)

    def test_host_off_can_probe_but_never_requires_managed_dns(self):
        env = dict(self.env, FEILIAN_NETWORK_MODE="host", DNS_MODE="off")
        self.dns.active = False
        controller = self.controller(env)
        controller.once()
        snapshot = controller.once()
        self.assertTrue(snapshot["ready"])
        self.assertFalse(snapshot["evidence"]["dns_managed"])

    def test_dns_failure_never_logs_exception_or_preserves_ready(self):
        self.dns.failure = True
        snapshot = self.controller().once()
        self.assertFalse(snapshot["ready"])
        self.assertEqual(snapshot["reason"], "dns_configuration_failed")
        self.assertNotIn("do_not_log", json.dumps(snapshot))

    def test_status_has_only_bounded_redacted_evidence_and_owner_permissions(self):
        env = self.file_env(b'{"DNS":["10.20.0.53"],"password":"VERY_SECRET"}')
        self.controller(env).once()
        raw = (self.state_dir / "status.json").read_text()
        for forbidden in ("VERY_SECRET", "password", "https://", "health.corp.test", "vpn.conf"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual((self.state_dir / "status.json").stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.store.read()["reason"], "status_invalid")

    def test_status_and_check_are_readonly_even_when_missing(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(vpn.main(["status", "--state-dir", str(self.state_dir)]), 0)
            self.assertEqual(vpn.main(["check", "--state-dir", str(self.state_dir)]), 1)
        self.assertFalse(self.state_dir.exists())

    def test_status_ttl_and_future_time_fail_readiness_without_rewriting(self):
        controller = self.controller()
        controller.once()
        controller.once()
        original = (self.state_dir / "status.json").read_bytes()
        self.clock.advance(21)
        self.assertFalse(self.store.read()["ready"])
        self.assertFalse(self.store.read()["live"])
        self.assertEqual(self.store.read()["reason"], "heartbeat_expired")
        self.assertEqual((self.state_dir / "status.json").read_bytes(), original)
        self.clock.advance(-100)
        self.assertEqual(self.store.read()["reason"], "heartbeat_expired")

    def test_status_invalid_types_unknown_fields_and_symlinks_fail_closed(self):
        good = vpn.make_status("READY", "all_probes_passed", self.clock.time())
        mutations = [dict(good, schema_version=True), dict(good, ready="yes"), dict(good, live=False),
                     dict(good, state="UNKNOWN"), dict(good, unexpected=1), dict(good, updated_at=None),
                     dict(good, evidence={"url": "https://secret/"}), dict(good, evidence={"vpn_ipv4": [None]}),
                     dict(good, evidence={"success_count": True}), dict(good, evidence={"dns_active": "yes"})]
        self.state_dir.mkdir(mode=0o700)
        status = self.state_dir / "status.json"
        for value in mutations:
            status.write_text(json.dumps(value))
            with self.subTest(value=value):
                self.assertEqual(self.store.read()["reason"], "status_invalid")
        status.unlink()
        target = self.root / "target.json"
        target.write_text(json.dumps(good))
        status.symlink_to(target)
        self.assertEqual(self.store.read()["reason"], "status_invalid")
        with self.assertRaises(vpn.DNSError):
            self.store.publish(good)
        self.assertEqual(json.loads(target.read_text()), good)

    def test_drain_wins_over_inflight_ready_publication(self):
        controller = self.controller()
        controller.once()
        snapshot = self.store.drain()
        self.assertEqual(snapshot["state"], "DRAINING")
        self.assertFalse(snapshot["ready"])
        self.assertEqual(self.store.publish(vpn.make_status("READY", "all_probes_passed", self.clock.time()))["state"], "DRAINING")
        previous_calls = len(self.runner.calls)
        self.assertEqual(controller.once()["state"], "DRAINING")
        self.assertEqual(len(self.runner.calls), previous_calls)

    def test_disconnection_after_ready_does_not_kill_liveness(self):
        controller = self.controller()
        controller.once()
        controller.once()
        self.runner.fail = True
        snapshot = controller.once()
        self.assertEqual(snapshot["state"], "DISCONNECTED")
        self.assertTrue(snapshot["live"])
        self.assertFalse(snapshot["ready"])

    def test_total_budget_expiry_is_an_explicit_probe_failure(self):
        def resolve(*_, **__):
            self.clock.advance(vpn.PROBE_BUDGET + 1)
            return ("10.20.30.40",)
        self.resolver.resolve = resolve
        self.assertEqual(self.controller().once()["reason"], "probe_budget_expired")

    def test_run_finally_drains_and_restores_only_owned_dns(self):
        controller = self.controller()
        self.clock.sleep = mock.Mock(side_effect=RuntimeError("stop offline loop"))
        with self.assertRaisesRegex(RuntimeError, "stop offline loop"):
            controller.run()
        snapshot = self.store.read()
        self.assertEqual(snapshot["state"], "DRAINING")
        self.assertFalse(snapshot["live"])
        self.assertFalse(snapshot["ready"])
        self.assertEqual(self.dns.restored, 1)
        self.assertEqual(self.dns.closed, 1)

    def test_invalid_core_environment_rejected_without_network(self):
        bad_values = [("FEILIAN_NETWORK_MODE", "auto"), ("VPN_IFACE", "tun0;exit"),
                      ("VPN_DNS_SOURCE", "process"), ("VPN_DNS", "127.0.0.1"),
                      ("CORP_DOMAINS", "corp.test\nserver=8.8.8.8"), ("CORP_CIDRS", "0.0.0.0/0"),
                      ("VPN_PROBE_DNS_NAME", "evilcorp.test"),
                      ("VPN_PROBE_URL", "http://health.corp.test/"),
                      ("VPN_PROBE_URL", "https://user:secret@health.corp.test/"),
                      ("VPN_PROBE_URL", "https://health.corp.test:bad/"),
                      ("VPN_PROBE_URL", "https://evilcorp.test/"),
                      ("VPN_PROBE_EXPECT_STATUS", "302"), ("VPN_CONFIG_FILE", "relative/vpn.conf"),
                      ("VPN_PROBE_CA_FILE", "relative/ca.pem")]
        for key, value in bad_values:
            with self.subTest(key=key, value=value), self.assertRaises(vpn.ConfigError):
                vpn.Config.from_env(dict(self.env, **{key: value}))
        with self.assertRaisesRegex(vpn.ConfigError, "host_requires_dns_off"):
            vpn.Config.from_env(dict(self.env, FEILIAN_NETWORK_MODE="host"))
        self.assertFalse(self.runner.calls)

    def test_route_withdrawn_during_https_cannot_publish_ready(self):
        def during_probe(*_args, **_kwargs):
            self.runner.route_devices["10.20.30.40"] = "eth0"
            return 200
        self.http.probe = during_probe
        snapshot = self.controller().once()
        self.assertEqual(snapshot["reason"], "target_not_routed_via_vpn")
        self.assertFalse(snapshot["ready"])

    def test_ready_state_requires_complete_consistent_evidence(self):
        controller = self.controller()
        controller.once()
        ready = controller.once()
        self.assertTrue(self.store.read()["ready"])
        path = self.state_dir / "status.json"
        mutations = [dict(ready, evidence={}), dict(ready, ready=False)]
        for key, value in (("success_count", 0), ("dns_active", False), ("target_count", 0), ("dns_mode", "off")):
            mutations.append(dict(ready, evidence=dict(ready["evidence"], **{key: value})))
        for value in mutations:
            path.write_text(json.dumps(value))
            with self.subTest(value=value):
                self.assertEqual(self.store.read()["reason"], "status_invalid")

    def test_group_writable_state_or_status_file_is_not_trusted(self):
        self.controller().once()
        path = self.state_dir / "status.json"
        path.chmod(0o620)
        self.assertEqual(self.store.read()["reason"], "status_invalid")
        path.chmod(0o600)
        self.state_dir.chmod(0o720)
        self.assertEqual(self.store.read()["reason"], "status_invalid")
        self.state_dir.chmod(0o700)

    def test_optional_ca_is_regular_absolute_and_passed_to_https(self):
        ca = self.root / "test-ca.pem"
        ca.write_text("offline placeholder; HTTPS stub does not open it")
        self.controller(dict(self.env, VPN_PROBE_CA_FILE=str(ca))).once()
        self.assertEqual(self.http.calls[0][0][4], ca)
        link = self.root / "ca-link.pem"
        link.symlink_to(ca)
        with self.assertRaises(vpn.ConfigError):
            vpn.Config.from_env(dict(self.env, VPN_PROBE_CA_FILE=str(link)))


class ProtocolTests(unittest.TestCase):
    @staticmethod
    def name(value):
        return b"".join(bytes((len(part),)) + part.encode() for part in value.split(".")) + b"\0"

    def packet(self, *, ident=42, flags=0x8180, ttl=30, answer_name=b"\xc0\x0c", address="10.20.30.40"):
        question = self.name("health.corp.test") + b"\0\1\0\1"
        answer = answer_name + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(address)
        return struct.pack("!HHHHHH", ident, flags, 1, 1, 0, 0) + question + answer

    def test_dns_a_answer_is_bounded_and_question_specific(self):
        self.assertEqual(vpn.DNSResolver.parse(self.packet(), 42, "health.corp.test"), ("10.20.30.40",))
        for packet in (self.packet(ident=43), self.packet(flags=0x8183), self.packet(flags=0x8380),
                       self.packet(ttl=0), self.packet(answer_name=self.name("unrelated.corp.test")), b"\0" * 11):
            with self.subTest(packet=packet[:20]), self.assertRaises(vpn.ProbeError):
                vpn.DNSResolver.parse(packet, 42, "health.corp.test")

    def test_dns_cname_chain_is_followed_but_compression_cycles_are_rejected(self):
        question = self.name("health.corp.test") + b"\0\1\0\1"
        target = self.name("real.corp.test")
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 30, len(target)) + target
        answer = target + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("10.20.30.40")
        packet = struct.pack("!HHHHHH", 42, 0x8180, 1, 2, 0, 0) + question + cname + answer
        self.assertEqual(vpn.DNSResolver.parse(packet, 42, "health.corp.test"), ("10.20.30.40",))
        with self.assertRaises(vpn.ProbeError):
            vpn.DNSResolver._name(b"\xc0\x00", 0)

    def test_urllib_has_explicit_empty_proxy_handler_no_redirect_and_verified_context(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.getcode.return_value = 200
        response.geturl.return_value = "https://health.corp.test/"
        opener = mock.Mock()
        opener.open.return_value = response
        context = mock.Mock(spec=ssl.SSLContext)
        with mock.patch.object(vpn.ssl, "create_default_context", return_value=context) as create_context, \
                mock.patch.object(vpn.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(vpn.HTTPSProbe().probe("https://health.corp.test/", "10.20.30.40", "10.20.0.2", 200), 200)
        handlers = build.call_args.args
        self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsNone(handlers[2].redirect_request(None, None, 302, "login", {}, "https://public.test"))
        create_context.assert_called_once_with(cafile=None)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 3)

    def test_http_redirect_and_certificate_failure_are_never_followed_or_ignored(self):
        for failure in (urllib.error.HTTPError("https://health.corp.test", 302, "login", {}, None),
                        urllib.error.URLError(ssl.SSLCertVerificationError("untrusted"))):
            opener = mock.Mock()
            opener.open.side_effect = failure
            with mock.patch.object(vpn.ssl, "create_default_context", return_value=mock.Mock()), \
                    mock.patch.object(vpn.urllib.request, "build_opener", return_value=opener), \
                    self.assertRaises(vpn.ProbeError):
                vpn.HTTPSProbe().probe("https://health.corp.test/", "10.20.30.40", "10.20.0.2", 200)
            self.assertEqual(opener.open.call_count, 1)

    def test_pinned_tls_connect_preserves_hostname_source_and_does_not_resolve_hostname(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with mock.patch.object(vpn.socket, "create_connection", return_value=mock.Mock()) as connect, \
                mock.patch.object(vpn.ssl.SSLContext, "wrap_socket", return_value=mock.Mock()) as wrap:
            connection = vpn._PinnedConnection("health.corp.test:443", pinned_ip="10.20.30.40",
                                                source_ip="10.20.0.2", context=context, timeout=2)
            connection.connect()
            connect.assert_called_once_with(("10.20.30.40", 443), 2, ("10.20.0.2", 0))
            self.assertEqual(wrap.call_args.kwargs["server_hostname"], "health.corp.test")
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            connection.close()


if __name__ == "__main__":
    unittest.main()
