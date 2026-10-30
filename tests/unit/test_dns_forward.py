"""Offline tests for the split DNS forwarder: no real resolvers or network."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dns_forward", ROOT / "runtime" / "dns_forward.py")
fwd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fwd)


def make_query(name: str, ident: int = 0x1234) -> bytes:
    q = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


class PolicyTests(unittest.TestCase):
    def policy(self, text):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "dnsmasq.servers"
        path.write_text(text)
        return fwd.load_policy(path), path

    def test_parses_default_domain_and_interface_binding(self):
        policy, _ = self.policy(
            "# comment\nserver=127.0.0.11\nserver=/corp.test/10.91.0.53@labtun0\n")
        self.assertEqual(policy["defaults"], [("127.0.0.11", "")])
        self.assertEqual(policy["domains"]["corp.test"], ("10.91.0.53", "labtun0"))

    def test_blocked_domain_has_no_upstream(self):
        policy, _ = self.policy("server=127.0.0.11\nserver=/corp.test/\n")
        self.assertEqual(policy["domains"]["corp.test"], (None, ""))

    def test_rejects_unknown_directives_and_bad_interfaces(self):
        for text in ("address=/x/1.2.3.4\n", "server=/corp.test/10.91.0.53@bad iface\n",
                     "server=\n", "server=//1.2.3.4\n"):
            with self.subTest(text=text), self.assertRaises(fwd.PolicyError):
                self.policy(text)

    def test_policy_symlink_is_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        real = Path(tmp.name) / "real"
        real.write_text("server=127.0.0.11\n")
        link = Path(tmp.name) / "link"
        link.symlink_to(real)
        with self.assertRaises(fwd.PolicyError):
            fwd.load_policy(link)


class SelectionTests(unittest.TestCase):
    def test_longest_suffix_wins_and_blocked_domain_never_falls_back(self):
        policy = {"defaults": [("127.0.0.11", "")],
                  "domains": {"corp.test": ("10.91.0.53", "labtun0"),
                              "deep.corp.test": ("10.91.0.54", ""),
                              "off.test": (None, "")}}
        self.assertEqual(fwd.select_upstream(policy, "health.corp.test"), ("10.91.0.53", "labtun0", False))
        self.assertEqual(fwd.select_upstream(policy, "a.deep.corp.test"), ("10.91.0.54", "", False))
        self.assertEqual(fwd.select_upstream(policy, "x.off.test"), (None, "", True))
        self.assertEqual(fwd.select_upstream(policy, "example.com"), ("127.0.0.11", "", False))
        # A suffix must match on a label boundary, not as a substring.
        self.assertEqual(fwd.select_upstream(policy, "notcorp.test"), ("127.0.0.11", "", False))

    def test_no_default_and_no_match_is_fail_closed(self):
        policy = {"defaults": [], "domains": {}}
        self.assertEqual(fwd.select_upstream(policy, "example.com"), (None, "", True))


class MessageTests(unittest.TestCase):
    def test_query_parsing_and_synthetic_answers(self):
        query = make_query("health.corp.test")
        name, end = fwd._qname(query)
        self.assertEqual(name, "health.corp.test")
        self.assertEqual(end, len(query))
        self.assertEqual(fwd._nxdomain(query)[2:4], b"\x81\x83")
        self.assertEqual(fwd._servfail(query)[2:4], b"\x81\x82")

    def test_malformed_query_is_rejected(self):
        with self.assertRaises(fwd.PolicyError):
            fwd._qname(b"\x00\x01")

    def test_servfail_survives_a_malformed_query(self):
        # A malformed datagram used to make the error path re-parse the query and
        # raise, killing the forwarder process outright.
        self.assertEqual(fwd._servfail(b""), b"")  # nothing to echo back
        for bad in (b"\x00\x01\x02", b"\xff" * 4, b"\x12\x34garbage"):
            with self.subTest(bad=bad):
                reply = fwd._servfail(bad)
                self.assertEqual(reply[2:4], b"\x81\x82")

    def test_forward_returns_only_matching_transaction(self):
        policy_sock = mock.Mock()
        policy_sock.recvfrom.side_effect = [(b"\x99\x99stray", ("1.1.1.1", 53)),
                                            (b"\x12\x34answer", ("1.1.1.1", 53))]
        with mock.patch.object(fwd.socket, "socket", return_value=policy_sock):
            reply = fwd.forward(make_query("health.corp.test"), "10.91.0.53", "labtun0")
        self.assertEqual(reply, b"\x12\x34answer")
        self.assertTrue(policy_sock.setsockopt.called)
        self.assertTrue(policy_sock.close.called)

    def test_forward_timeout_is_none_not_a_guess(self):
        policy_sock = mock.Mock()
        policy_sock.recvfrom.side_effect = socket.timeout()
        with mock.patch.object(fwd.socket, "socket", return_value=policy_sock):
            self.assertIsNone(fwd.forward(make_query("health.corp.test"), "10.91.0.53", ""))


if __name__ == "__main__":
    unittest.main()
