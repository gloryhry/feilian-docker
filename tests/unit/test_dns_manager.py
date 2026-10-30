"""Offline DNS ownership/config tests. No real dnsmasq, network or /etc writes."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from runtime import dns_manager as dns
from runtime.dns_manager import DNSManager, DNSError, PidReloader, domain_name, dns_addresses, secure_directory


class SyntaxStub:
    def __init__(self):
        self.calls = []
        self.reject = False

    def run(self, args, timeout):
        assert args[:2] == ["dnsmasq", "--test"]
        candidate = Path(args[2].split("=", 1)[1])
        main = candidate.read_text()
        servers_path = Path(next(line.split("=", 1)[1] for line in main.splitlines() if line.startswith("servers-file=")))
        self.calls.append((main, servers_path.read_text(), timeout))
        return SimpleNamespace(returncode=1 if self.reject else 0)


class ReloaderStub:
    def __init__(self):
        self.running = True
        self.calls = 0
        self.reject = False

    def active(self):
        return self.running

    def reload(self):
        self.calls += 1
        if self.reject:
            raise DNSError("injected_reload_failure")


class DNSManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.resolv = self.root / "resolv.conf"
        self.original = b"# Docker bootstrap\nnameserver 127.0.0.11\nsearch local.test\n"
        self.resolv.write_bytes(self.original)
        self.inode = self.resolv.stat().st_ino
        self.runner = SyntaxStub()
        self.reloader = ReloaderStub()
        self.ifindex = 7
        self.interface = "labvpn0"
        self.manager = self.make_manager()

    def iface_index(self, name):
        if name != self.interface:
            raise OSError("no such interface")
        return self.ifindex

    def make_manager(self, **kwargs):
        kwargs.setdefault("ifindex_resolver", self.iface_index)
        return DNSManager(self.state, self.resolv, self.runner, self.reloader, **kwargs)

    def tearDown(self):
        self.manager.close()
        self.tmp.cleanup()

    def apply(self, connected=False, servers=(), domains=("corp.test",), mode="split"):
        # Connected mode must carry the observed VPN interface/ifindex generation.
        if connected:
            return self.manager.apply(connected, servers, domains, mode,
                                      vpn_interface=self.interface, vpn_ifindex=self.ifindex)
        return self.manager.apply(connected, servers, domains, mode)

    def servers(self):
        return (self.state / "dnsmasq.servers").read_text()

    def test_prepare_before_daemon_preserves_bootstrap(self):
        self.reloader.running = False
        result = self.apply()
        self.assertFalse(result["active"])
        self.assertEqual(self.resolv.read_bytes(), self.original)
        main = self.manager.conf_path.read_text()
        for line in ("listen-address=127.0.0.1", "bind-interfaces", "no-resolv", "no-hosts", "user=root",
                     "pid-file=" + str(self.state / "dnsmasq.pid"),
                     "servers-file=" + str(self.state / "dnsmasq.servers")):
            self.assertIn(line + "\n", main)
        self.assertIn("server=/corp.test/\n", self.servers())
        self.assertIn("server=127.0.0.11\n", self.servers())
        self.reloader.running = True
        self.apply()
        self.assertIn(b"nameserver 127.0.0.1\n", self.resolv.read_bytes())

    def test_split_multiple_vpn_dns_and_suffix_boundaries(self):
        self.apply(True, ("10.20.0.53", "10.20.0.54"), ("Corp.Test.", "office.test"))
        servers = self.servers()
        for domain in ("corp.test", "office.test"):
            for address in ("10.20.0.53", "10.20.0.54"):
                self.assertIn(f"server=/{domain}/{address}@{self.interface}\n", servers)
        self.assertNotIn("server=/test/", servers)
        # Bootstrap resolvers are never pinned to the tunnel interface.
        self.assertIn("server=127.0.0.11\n", servers)
        self.assertNotIn("127.0.0.11@", servers)
        self.assertEqual(self.resolv.stat().st_ino, self.inode)
        self.assertEqual(self.reloader.calls, 1)
        self.apply(True, ("10.20.0.53", "10.20.0.54"), ("corp.test", "office.test"))
        self.assertEqual(self.reloader.calls, 1, "identical snapshots need not flush cache")

    def test_disconnect_keeps_local_only_corporate_block_and_flushes_cache(self):
        self.apply(True, ("10.20.0.53",))
        self.apply()
        self.assertIn("server=/corp.test/\n", self.servers())
        self.assertNotIn("10.20.0.53", self.servers())
        self.assertIn("server=127.0.0.11\n", self.servers())
        self.assertEqual(self.reloader.calls, 2)
        self.assertEqual(self.resolv.stat().st_ino, self.inode)

    def test_full_connected_uses_only_vpn_general_servers(self):
        self.apply(True, ("10.20.0.53", "10.20.0.54"), mode="full")
        self.assertIn(f"server=10.20.0.53@{self.interface}\nserver=10.20.0.54@{self.interface}\n", self.servers())
        self.assertNotIn("127.0.0.11", self.servers())
        self.apply(mode="full")
        self.assertIn("server=127.0.0.11\n", self.servers())
        self.assertIn("server=/corp.test/\n", self.servers())

    def test_auto_mode_selection(self):
        self.assertEqual(self.apply(mode="auto")["mode"], "split")
        self.assertEqual(self.apply(domains=(), mode="auto")["mode"], "full")

    def test_split_requires_domains(self):
        with self.assertRaisesRegex(DNSError, "split_requires"):
            self.apply(domains=())
        self.assertFalse(self.state.exists())

    def test_host_off_does_not_even_create_state_directory(self):
        self.manager.close()
        self.manager = self.make_manager(network_mode="host")
        self.assertEqual(self.manager.apply(False, mode="off"), {"managed": False, "active": False, "mode": "off"})
        self.assertFalse(self.state.exists())
        self.assertEqual(self.resolv.read_bytes(), self.original)
        with self.assertRaisesRegex(DNSError, "host_requires"):
            self.manager.apply(False, mode="full")
        self.assertFalse(self.runner.calls)

    def test_invalid_modes_are_rejected_before_writes(self):
        with self.assertRaisesRegex(DNSError, "invalid_dns_mode"):
            self.apply(mode="surprise")
        self.assertFalse(self.state.exists())

    def test_syntax_failure_preserves_last_known_good(self):
        self.apply(True, ("10.20.0.53",))
        before = {name: (self.state / name).read_bytes() for name in ("dnsmasq.conf", "dnsmasq.servers", "dns-owner.json")}
        resolver_before = self.resolv.read_bytes()
        self.runner.reject = True
        with self.assertRaisesRegex(DNSError, "dns_syntax_rejected"):
            self.apply(True, ("10.20.0.54",))
        for name, content in before.items():
            self.assertEqual((self.state / name).read_bytes(), content)
        self.assertEqual(self.resolv.read_bytes(), resolver_before)
        self.assertEqual(self.reloader.calls, 1)
        self.assertFalse(list(self.state.glob(".dns-*")))

    def test_reload_failure_rolls_servers_back(self):
        self.apply(True, ("10.20.0.53",))
        before = self.servers()
        self.reloader.reject = True
        with self.assertRaisesRegex(DNSError, "dnsmasq_reload_failed"):
            self.apply(True, ("10.20.0.54",))
        self.assertEqual(self.servers(), before)

    def test_restore_preserves_inode_and_original_exactly(self):
        self.apply()
        self.assertTrue(self.manager.restore())
        self.assertEqual(self.resolv.read_bytes(), self.original)
        self.assertEqual(self.resolv.stat().st_ino, self.inode)
        self.assertFalse(self.manager.restore())

    def test_later_third_party_resolver_edit_is_never_overwritten(self):
        self.apply()
        later = b"nameserver 192.0.2.53\n# third-party owner\n"
        self.resolv.write_bytes(later)
        self.assertFalse(self.manager.restore())
        with self.assertRaisesRegex(DNSError, "resolv_ownership_lost"):
            self.apply()
        self.assertEqual(self.resolv.read_bytes(), later)

    def test_later_resolver_inode_replacement_is_not_restored(self):
        self.apply()
        replacement = self.root / "replacement"
        replacement.write_bytes(self.resolv.read_bytes())
        replacement.replace(self.resolv)
        self.assertFalse(self.manager.restore())
        self.assertNotEqual(self.resolv.stat().st_ino, self.inode)

    def test_resolver_symlink_is_not_followed(self):
        target = self.root / "symlink-target"
        target.write_bytes(self.original)
        self.resolv.unlink()
        self.resolv.symlink_to(target)
        with self.assertRaisesRegex(DNSError, "dns_owner_conflict"):
            self.apply()
        self.assertEqual(target.read_bytes(), self.original)

    def test_private_config_symlink_and_unknown_config_are_not_overwritten(self):
        self.state.mkdir(mode=0o700)
        target = self.root / "untouched"
        target.write_text("third party\n")
        (self.state / "dnsmasq.conf").symlink_to(target)
        with self.assertRaisesRegex(DNSError, "dns_owner_conflict"):
            self.apply()
        self.assertEqual(target.read_text(), "third party\n")

    def test_external_config_edit_loses_ownership(self):
        self.apply()
        path = self.state / "dnsmasq.servers"
        path.write_text("server=192.0.2.53\n")
        with self.assertRaisesRegex(DNSError, "dns_config_ownership_lost"):
            self.apply(True, ("10.20.0.53",))
        self.assertEqual(path.read_text(), "server=192.0.2.53\n")

    def test_only_one_dns_owner(self):
        self.apply()
        second = self.make_manager()
        try:
            with self.assertRaisesRegex(DNSError, "dns_owner_busy"):
                second.apply(False, domains=("corp.test",), mode="split")
        finally:
            second.close()

    def test_restart_adopts_ownership_without_losing_original(self):
        self.apply()
        self.manager.close()
        self.manager = self.make_manager()
        self.apply(True, ("10.20.0.53",))
        self.assertTrue(self.manager.restore())
        self.assertEqual(self.resolv.read_bytes(), self.original)

    def test_private_files_are_owner_only(self):
        self.apply()
        for name in ("dns-owner.json", "dnsmasq.conf", "dnsmasq.servers", "dns-owner.lock"):
            self.assertEqual((self.state / name).stat().st_mode & 0o777, 0o600)

    def test_invalid_domains_and_dns_cannot_inject_configuration(self):
        for domain in ("*.corp.test", "corp.test\nserver=8.8.8.8", "corp/test", "local"):
            with self.subTest(domain=domain), self.assertRaises(DNSError):
                domain_name(domain)
        for address in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.0.1", "fe80::1%eth0", "10.0.0.53\nserver=8.8.8.8"):
            with self.subTest(address=address), self.assertRaises(DNSError):
                dns_addresses((address,))

    def test_state_directory_symlink_traversal_and_newline_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        for path in (link / "state", self.root / "x/../state", self.root / "bad\nname"):
            with self.subTest(path=path), self.assertRaises(DNSError):
                secure_directory(path)

    def test_concurrent_partial_write_is_not_accepted_as_a_stable_snapshot(self):
        path = self.root / "partial.json"
        path.write_bytes(b'{"DNS":["10.20.0.53"]}')
        original_read = os.read

        def changing_read(fd, size):
            result = original_read(fd, size)
            path.write_bytes(b"{")
            return result

        with mock.patch.object(dns.os, "read", side_effect=changing_read), self.assertRaisesRegex(DNSError, "unstable_private_file"):
            dns.read_regular(path)

    def test_fifo_is_rejected_without_blocking(self):
        path = self.root / "fifo"
        os.mkfifo(path)
        with self.assertRaisesRegex(DNSError, "invalid_private_file"):
            dns.read_regular(path)

    def test_unverified_pid_never_signals_other_process(self):
        self.state.mkdir(mode=0o700)
        pid = self.state / "dnsmasq.pid"
        reloader = PidReloader(pid, self.state / "dnsmasq.conf")
        for value in ("-1", "1", "0", str(os.getpid()), "1;kill", "9" * 20):
            pid.write_text(value)
            self.assertFalse(reloader.active())
            with self.assertRaisesRegex(DNSError, "dnsmasq_pid_unverified"):
                reloader.reload()


if __name__ == "__main__":
    unittest.main()
