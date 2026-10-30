#!/usr/bin/env python3
"""Explicit Docker-only L2/L3 driver; import has no side effects.

All resources are uniquely named and carry an exact owner label. There is no
host mode, sudo, nsenter, host capture, global prune, public official cache or
bind-mounted host directory. L2 uses a REAL TUN carrying test IPv4 over isolated
plaintext UDP; this is NOT FeiLian's protocol and cannot certify an official VPN.
Probe consumers are separate containers: proxy probes share the app netns because
production proxies intentionally bind loopback; gateway probes use an independent
access network. Capture is a test-only NET_RAW sidecar, never a host tcpdump.

Incomplete checks are required FAIL/NOT_IMPLEMENTED, never a PASS placeholder.
"""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import time

OWNER = "io.feilian.test.owner"
CORP = "10.91.0.0/24"


class LabError(Exception):
    pass


DNS_DIAG = r"""
import socket, struct, sys

def query(name, server, timeout=12):
    tid = 0x4242
    q = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    for label in name.split('.'):
        q += bytes([len(label)]) + label.encode()
    q += b'\x00' + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(512)
        return 'ok(%d bytes)' % len(data)
    except Exception as exc:
        return '%s: %s' % (type(exc).__name__, exc)
    finally:
        s.close()

print('servers-file:', open('/run/feilian/dnsmasq.servers').read().strip().replace(chr(10), ' | '))
def query_bound(name, server, device, timeout=8):
    tid = 0x4343
    q = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    for label in name.split('.'):
        q += bytes([len(label)]) + label.encode()
    q += b'\x00' + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.setsockopt(socket.SOL_SOCKET, 25, device.encode() + b'\x00')  # SO_BINDTODEVICE
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(512)
        return 'ok(%d bytes)' % len(data)
    except Exception as exc:
        return '%s: %s' % (type(exc).__name__, exc)
    finally:
        s.close()

import subprocess as _sp
_ss = _sp.run(['ss', '-ltnp'], capture_output=True, text=True).stdout
print('listeners:', ' | '.join(l.strip() for l in _ss.splitlines() if ':8118' in l or ':1080' in l)[:300])
for _port in (8118, 1080):
    try:
        _c = socket.create_connection(('127.0.0.1', _port), timeout=3); _c.close()
        print('connect %d: ok' % _port)
    except Exception as _exc:
        print('connect %d: %s %s' % (_port, type(_exc).__name__, _exc))
try:
    _s = socket.create_connection(('127.0.0.1', 8118), timeout=3)
    _s.sendall(b'GET http://health.corp.test/health HTTP/1.1\r\nHost: health.corp.test\r\n\r\n')
    _s.settimeout(5)
    print('raw-8118:', _s.recv(120).decode('latin-1').splitlines()[0][:100])
    _s.close()
except Exception as _exc:
    print('raw-8118: %s %s' % (type(_exc).__name__, _exc))
print('via-corp-dns-bound:', query_bound('health.corp.test', '10.91.0.53', 'labtun0'))
print('via-local-resolver:', query('health.corp.test', '127.0.0.1'))
print('via-corp-dns:', query('health.corp.test', '10.91.0.53'))
try:
    c = socket.create_connection(('10.91.0.80', 443), timeout=3)
    print('tcp-corp-443: ok')
    c.close()
except Exception as exc:
    print('tcp-corp-443:', type(exc).__name__, exc)
"""


class Lab:
    def __init__(self, driver, args):
        self.driver, self.args = driver, args
        self.owner = args.run_id
        self.state = driver.root / ".state" / "verification" / self.owner / "lab"
        self.names = {kind: self.owner + "-" + kind for kind in
                      ("bootstrap-net", "access-net", "bootstrap", "relay", "app", "consumer", "gateway", "capture", "data", "secrets", "home", "root", "logs", "sentinel")}
        self.resources = []
        self.image = args.image or "feilian-mock:" + self.owner
        self.probe = "feilian-probe:" + self.owner
        self.boot_ip = None
        self.app_ip = None

    def add(self, kind, name, *arguments):
        command = {"container": ("create",), "network": ("network", "create"), "volume": ("volume", "create")}[kind]
        # Container label position precedes image; network/volume names are last.
        if kind == "container":
            result = self.driver.docker(*command, "--name", name, "--label", OWNER + "=" + self.owner, *arguments)
        else:
            result = self.driver.docker(*command, "--label", OWNER + "=" + self.owner, *arguments, name)
        if (kind, name) not in self.resources:
            self.resources.append((kind, name))
        return result

    def inspect(self, kind, name):
        return self.driver.inspect(name, kind)

    def owned(self, kind, name):
        value = self.inspect(kind, name)
        labels = (value.get("Config", {}).get("Labels", {}) if kind == "container" else value.get("Labels", {})) or {}
        return labels.get(OWNER) == self.owner

    def cleanup(self):
        ok = True
        for kind, name in reversed(self.resources):
            try:
                if not self.owned(kind, name):
                    ok = False  # Never delete a resource somebody else replaced.
                    continue
                command = ("rm", "--force", name) if kind == "container" else (kind, "rm", name)
                self.driver.docker(*command, check=False)
            except Exception:
                ok = False
        self.driver.report.add("cleanup.owned_resources", "PASS" if ok else "FAIL", "exact_owner_only_no_global_prune")
        return ok

    def certificates(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=False)
        commands = [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=Feilian isolated test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(self.state / "ca.key"), "-out", str(self.state / "ca.crt")],
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=health.corp.test", "-keyout", str(self.state / "server.key"), "-out", str(self.state / "server.csr")],
            ["openssl", "x509", "-req", "-in", str(self.state / "server.csr"), "-CA", str(self.state / "ca.crt"), "-CAkey", str(self.state / "ca.key"), "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(self.state / "server.ext"), "-out", str(self.state / "server.crt")],
        ]
        (self.state / "server.ext").write_text("subjectAltName=DNS:health.corp.test,DNS:login.public.test,IP:10.91.0.80\nextendedKeyUsage=serverAuth\n")
        for command in commands:
            self.driver.call(command, timeout=60)
        for path in self.state.iterdir():
            path.chmod(0o600)
        # The fixtures are throwaway material inside an isolated, per-run network.
        # The service containers run with --cap-drop ALL (so no DAC_OVERRIDE) and a
        # different uid owns these files, therefore TLS material must be readable by
        # "others" or the fixture dies with PermissionError before any check runs.
        for name in ("ca.crt", "server.crt", "server.key"):
            (self.state / name).chmod(0o644)

    def setup_networks(self):
        for kind in ("bootstrap-net", "access-net"):
            self.add("network", self.names[kind], "--internal", "--driver", "bridge")
        for kind in ("data", "secrets", "home", "root", "logs"):
            self.add("volume", self.names[kind])

    def service(self, role, capabilities):
        arguments = ["--network", self.names["bootstrap-net"], "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--env", "FEILIAN_TEST_OWNER=" + self.owner,
                     "--mount", "type=volume,source=" + self.names["data"] + ",target=/labstate"]
        for capability in capabilities:
            arguments += ["--cap-add", capability]
        if role == "relay":
            arguments += ["--device", "/dev/net/tun:/dev/net/tun"]
        actual = "corp" if role == "relay" else "bootstrap"
        self.add("container", self.names[role], *arguments, self.probe, actual, "--owner", self.owner)

    def ip(self, role, network="bootstrap-net"):
        info = self.inspect("container", self.names[role])
        return info["NetworkSettings"]["Networks"][self.names[network]]["IPAddress"]

    def app(self, suite, overrides=None):
        args = ["--network", self.names["bootstrap-net"], "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--device", "/dev/net/tun:/dev/net/tun", "--shm-size", "256m"]
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP", "NET_BIND_SERVICE", "NET_RAW", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE", "SETFCAP", "NET_ADMIN"):
            args += ["--cap-add", capability]
        for role, destination in (("home", "/home/feilian"), ("root", "/root"), ("logs", "/var/log/feilian"), ("secrets", "/run/feilian-secrets")):
            args += ["--mount", f"type=volume,source={self.names[role]},target={destination}"]
        env = {"NET_MODE": "bridge", "FEILIAN_NETWORK_MODE": "bridge", "PROJECT_NAME": self.owner,
               "FEILIAN_TEST_OWNER": self.owner, "WEB_AUTH": "1", "WEB_TLS": "off", "WEB_BIND": "127.0.0.1",
               "START_NETWORKMANAGER": "0", "START_SERVICE": "1", "START_GUI": "1", "PROXY_BIND": "127.0.0.1"}
        if suite == "mock":
            env.update(FEILIAN_DNS_DEBUG="1", FEILIAN_PROXY_DEBUG="1", CORP_DOMAINS="corp.test", CORP_CIDRS=CORP, DNS_MODE="split", VPN_DNS_SOURCE="manual",
                       VPN_DNS="10.91.0.53", VPN_IFACE="labtun0", VPN_PROBE_DNS_NAME="health.corp.test",
                       VPN_PROBE_URL="https://health.corp.test/health", VPN_PROBE_CA_FILE="/run/lab-ca.crt")
        else:
            env.update(CORP_DOMAINS="", CORP_CIDRS="", VPN_PROBE_DNS_NAME="", VPN_PROBE_URL="", DNS_MODE="off", PROXY_ENABLED="0", GUARD_ENABLED="0")
        env.update(overrides or {})
        for key, value in env.items():
            args += ["--env", key + "=" + value]
        self.add("container", self.names["app"], *args, self.image)
        if suite == "mock":
            self.driver.docker("cp", str(self.state / "ca.crt"), self.names["app"] + ":/run/lab-ca.crt")
            self.driver.docker("cp", str(self.driver.root / "tests/fixtures/integration/tun.py"), self.names["app"] + ":/run/lab-tun.py")
        self.driver.docker("start", self.names["app"])

    def wait_data_plane(self, timeout=45):
        """VPN READY does not mean the proxies accept connections yet; the
        supervisor opens the data plane afterwards and publishes data_plane."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                state = json.loads(self.driver.docker(
                    "exec", self.names["app"], "cat", "/run/feilian/runtime.json").stdout)
                if state.get("data_plane") == "ready":
                    return
            except Exception:
                pass
            time.sleep(0.5)
        raise LabError("data_plane_timeout")

    def wait_status(self, ready, timeout=90):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                snapshot = self.driver.status(self.names["app"])
                if snapshot["live"] and snapshot["ready"] is ready:
                    return snapshot
            except Exception:
                pass
            time.sleep(0.5)
        raise LabError("runtime_status_timeout")

    def consumer(self):
        self.add("container", self.names["consumer"], "--network", "container:" + self.names["app"],
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                 "--mount", f"type=volume,source={self.names['data']},target=/labstate", self.probe, "idle")
        self.driver.docker("start", self.names["consumer"])

    def curl(self, proxy, url="https://health.corp.test/health", expected=True):
        args = ["exec", self.names["consumer"], "curl", "--silent", "--show-error", "--fail", "--noproxy", "",
                "--max-time", "6", "--proxy", proxy, "--cacert", "/labstate/ca.crt", url]
        result = self.driver.docker(*args, timeout=12, check=False)
        # Keep the reason so a FAIL row is diagnosable instead of a bare boolean.
        self.last_curl = " ".join(
            part for part in (str(result.returncode), result.stderr.decode("utf-8", "replace").strip()[:160]) if part)
        if expected:
            return result.returncode == 0 and b"CORP_TEST_ONLY" in result.stdout
        return result.returncode != 0

    def tunnel(self):
        app, relay = self.ip("app"), self.ip("relay")
        for role, address, peer, endpoint, script, routes in (
            ("relay", "10.254.0.2/30", "10.254.0.1", app, "/lab/tun.py", []),
            ("app", "10.254.0.1/30", "10.254.0.2", relay, "/run/lab-tun.py", ["--route", CORP]),
        ):
            self.driver.docker("exec", "--detach", self.names[role], "python3", "-B", script, "--owner", self.owner,
                               "--address", address, "--peer", peer, "--udp-peer", endpoint, *routes)

    def capture(self):
        # eth0 is the bootstrap interface of this deliberately ordered topology.
        self.add("container", self.names["capture"], "--network", "container:" + self.names["app"],
                 "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges:true",
                 "--mount", f"type=volume,source={self.names['data']},target=/labstate",
                 "--entrypoint", "tcpdump", self.probe, "-i", "eth0", "-p", "-nn", "-U", "-w", "/labstate/bootstrap.pcap", "not", "udp", "port", "4242")
        self.driver.docker("start", self.names["capture"])

    def corp_counter(self, name):
        code = ("import json,pathlib; p=pathlib.Path('/labstate/corp.jsonl'); "
                "print(sum(1 for l in p.read_text().splitlines() if json.loads(l).get('kind')=='dns' "
                "and json.loads(l).get('name')=='" + name + "') if p.exists() else 0)")
        return int(self.driver.docker("exec", self.names["relay"], "python3", "-c", code).stdout)

    def counter(self, name="health.corp.test"):
        code = ("import json,pathlib; p=pathlib.Path('/labstate/bootstrap.jsonl'); "
                "print(sum(1 for l in p.read_text().splitlines() if json.loads(l).get('kind')=='dns' and json.loads(l).get('name')=='" + name + "') if p.exists() else 0)")
        return int(self.driver.docker("exec", self.names["bootstrap"], "python3", "-c", code).stdout)

    def mock_checks(self):
        report = self.driver.report
        self.consumer()
        before = self.wait_status(False)
        report.add("mock.waiting_auth", "PASS" if before.get("state") in ("WAITING_AUTH", "UNCONFIGURED", "DEGRADED") else "FAIL", "no_test_tunnel_not_ready")
        report.add("proxy.before_ready", "PASS" if self.curl("socks5h://127.0.0.1:1080", expected=False) else "FAIL", "unready_data_plane_rejected")
        self.capture()
        self.tunnel()
        ready = self.wait_status(True)
        self.wait_data_plane()
        # Diagnose the DNS/return path while the data plane is still open; after
        # the fault steps the plane is closed and any inspection is misleading.
        diag = self.driver.docker("exec", self.names["app"], "python3", "-c", DNS_DIAG, check=False)
        report.add("diag.data_plane_window",
                   "PASS" if diag.returncode == 0 else "FAIL",
                   (diag.stdout or diag.stderr).decode("utf-8", "replace").strip()[:800], required=False)
        report.add("mock.real_kernel_tun", "PASS" if ready.get("evidence", {}).get("interface") == "labtun0" else "FAIL", "test_udp_transport_not_official_vpn")
        for name, proxy, url in (("http", "http://127.0.0.1:8118", "http://health.corp.test/health"),
                                 ("connect", "http://127.0.0.1:8118", "https://health.corp.test/health"),
                                 ("socks5h", "socks5h://127.0.0.1:1080", "https://health.corp.test/health")):
            passed = self.curl(proxy, url)
            report.add("proxy." + name, "PASS" if passed else "FAIL",
                       "internal_target_marker_and_verified_ca" if passed else "curl=" + getattr(self, "last_curl", "?"))
        query = self.driver.docker("exec", self.names["app"], "getent", "ahostsv4", "health.corp.test", check=False)
        split_ok = query.returncode == 0 and b"10.91.0.80" in query.stdout
        report.add("dns.connected_split", "PASS" if split_ok else "FAIL",
                   "corporate_dns_via_tunnel" if split_ok else "getent=" + query.stderr.decode("utf-8", "replace").strip()[:120])
        before_queries = self.counter()
        self.driver.docker("exec", self.names["app"], "ip", "link", "set", "dev", "labtun0", "down")
        self.wait_status(False)
        report.add("fault.interface_down", "PASS" if self.curl("socks5h://127.0.0.1:1080", expected=False) else "FAIL", "no_proxy_fallback_after_tunnel_loss")
        # Cached positive records must have expired before checking offline DNS.
        time.sleep(6)
        query = self.driver.docker("exec", self.names["app"], "getent", "ahostsv4", "health.corp.test", timeout=15, check=False)
        no_fallback = query.returncode != 0 and self.counter() == before_queries
        report.add("dns.disconnected_no_public_fallback", "PASS" if no_fallback else "FAIL", "no_bootstrap_corporate_query_or_stale_positive")
        self.driver.docker("exec", self.names["app"], "ip", "link", "set", "dev", "labtun0", "up")
        # Bringing the link back up does NOT restore the route the kernel dropped
        # while it was down; without this the harness would report the product as
        # stuck even though the product is correctly waiting for a route.
        self.driver.docker("exec", self.names["app"], "ip", "route", "replace", CORP,
                           "via", "10.254.0.2", "dev", "labtun0")
        self.wait_status(True)
        self.driver.docker("exec", self.names["app"], "ip", "route", "del", CORP, "via", "10.254.0.2", "dev", "labtun0")
        self.wait_status(False)
        report.add("fault.route_withdrawn", "PASS" if self.curl("socks5h://127.0.0.1:1080", expected=False) else "FAIL", "no_proxy_reroute_to_bootstrap")
        report.add("fault.ipv6_literal", "PASS" if self.curl("socks5h://127.0.0.1:1080", "https://[fd00:91::80]/", expected=False) else "FAIL", "unsupported_ipv6_proxy_path_rejected")
        self.driver.docker("stop", "--time", "3", self.names["capture"])
        packet = self.driver.docker("exec", self.names["consumer"], "tcpdump", "-Z", "root", "-nn", "-r",
                "/labstate/bootstrap.pcap", "net", CORP, check=False)
        parsed = packet.returncode == 0 and not packet.stdout.strip()
        detail = "container_netns_capture_excludes_test_udp_outer" if parsed else (
            "tcpdump_rc=%d out=%r err=%r" % (packet.returncode,
                                             packet.stdout.decode("utf-8", "replace")[:160],
                                             packet.stderr.decode("utf-8", "replace")[:160]))
        report.add("packets.no_plain_corporate_bootstrap", "PASS" if parsed else "FAIL", detail)
        self.driver.docker("cp", self.names["consumer"] + ":/labstate/bootstrap.pcap", str(self.state / "bootstrap.pcap"))
        try:
            # Killing the readiness controller must fail closed: the data plane has to
            # close and the proxies must stop, without waiting for a graceful drain.
            self.driver.docker("exec", self.names["app"], "pkill", "-f", "vpn_state.py", check=False)
            closed = False
            for _ in range(60):
                try:
                    state = json.loads(self.driver.docker(
                        "exec", self.names["app"], "cat", "/run/feilian/runtime.json").stdout)
                    if state.get("data_plane") == "closed":
                        closed = True
                        break
                except Exception:
                    pass
                time.sleep(0.5)
            # Probe inside the container: testing 127.0.0.1 from the host would
            # measure the host's own ports, not the app's data plane.
            listener = ("import socket,sys\n"
                        "open_ports=[]\n"
                        "for p in (8118,1080):\n"
                        "    s=socket.socket()\n"
                        "    s.settimeout(1)\n"
                        "    try:\n"
                        "        s.connect((chr(49)+chr(50)+chr(55)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49),p)); open_ports.append(p)\n"
                        "    except OSError:\n"
                        "        pass\n"
                        "    finally:\n"
                        "        s.close()\n"
                        "print(open_ports)\n")
            ports_closed = False
            for _ in range(20):
                probe = self.driver.docker("exec", self.names["app"], "python3", "-c", listener, check=False)
                if probe.returncode == 0 and probe.stdout.strip() in (b"[]", "[]"):
                    ports_closed = True
                    break
                time.sleep(0.5)
            report.add("fault.controller_exit",
                       "PASS" if closed and ports_closed else "FAIL",
                       "controller_death_closes_data_plane_and_proxies"
                       if closed and ports_closed else
                       "closed=%s ports_closed=%s" % (closed, ports_closed))

        except Exception as exc:
            report.add("fault.controller_exit", "FAIL",
                       "controller_exit_probe_failed_" + type(exc).__name__.lower())

        # Owned-only cleanup: a foreign nft table must survive while our own table
        # is removed. This is the claim that makes "cleanup" safe to run.
        try:
            self.driver.docker("exec", self.names["app"], "nft", "add", "table", "inet",
                               "feilian_foreign_probe", check=False)
            self.driver.docker("exec", self.names["app"], "python3",
                               "/opt/feilian/runtime/egress_policy.py", "cleanup",
                               "--context", "/run/feilian-proxy/context.json", check=False)
            tables = self.driver.docker("exec", self.names["app"], "nft", "list", "tables",
                                        check=False).stdout.decode("utf-8", "replace")
            foreign_kept = "feilian_foreign_probe" in tables
            owned_gone = "feilian_guard" not in tables
            report.add("cleanup.foreign_marker",
                       "PASS" if foreign_kept and owned_gone else "FAIL",
                       "foreign_table_preserved_and_owned_table_removed"
                       if foreign_kept and owned_gone else
                       "foreign_kept=%s owned_gone=%s" % (foreign_kept, owned_gone))
            self.driver.docker("exec", self.names["app"], "nft", "delete", "table", "inet",
                               "feilian_foreign_probe", check=False)
        except Exception as exc:
            report.add("cleanup.foreign_marker", "FAIL",
                       "cleanup_probe_failed_" + type(exc).__name__.lower())

        # DNS full mode: every name (not only corporate ones) must go to the VPN
        # resolver. Recreate the app with DNS_MODE=full and re-establish the tunnel.
        try:
            self.driver.docker("rm", "--force", self.names["app"], check=False)
            self.app("mock", {"DNS_MODE": "full", "CORP_DOMAINS": ""})
            self.tunnel()
            self.wait_status(True)
            policy = self.driver.docker("exec", self.names["app"], "cat",
                                        "/run/feilian/dnsmasq.servers", check=False).stdout.decode("utf-8", "replace")
            defaults = [line for line in policy.splitlines()
                        if line.startswith("server=") and "/" not in line]
            full_ok = (len(defaults) == 1 and "10.91.0.53" in defaults[0]
                       and "labtun0" in defaults[0] and "127.0.0.11" not in policy)
            before = self.corp_counter("example.test")
            self.driver.docker("exec", self.names["app"], "getent", "ahostsv4", "example.test",
                               timeout=15, check=False)
            via_vpn = self.corp_counter("example.test") > before
            report.add("dns.full_mode", "PASS" if full_ok and via_vpn else "FAIL",
                       "all_names_forwarded_to_vpn_resolver" if full_ok and via_vpn else
                       "defaults=%r vpn_queries_seen=%s" % (defaults, via_vpn))
        except Exception as exc:
            report.add("dns.full_mode", "FAIL", "full_mode_probe_failed_" + type(exc).__name__.lower())

        # Explicitly unfinished acceptance gates: do not let a partial test lab
        # turn these into successful or optional checks.
        for name in ("gateway.snat", "gateway.syn_mss", "auth.tls_wss", "fault.old_tcp"):
            report.add(name, "FAIL", "NOT_IMPLEMENTED")


def run(driver, suite, args):
    lab = Lab(driver, args)
    try:
        if suite == "mock":
            if args.image is None:
                driver.call(["bash", str(driver.root / "build.sh"), "--target", "mock", "--image", lab.image, "--load"], timeout=1200)
            if not lab.image.startswith("feilian-mock:"):
                raise LabError("mock_requires_independent_mock_tag")
            metadata = driver.inspect(lab.image, "image")
            if metadata.get("Config", {}).get("Labels", {}).get("io.feilian.client.kind") != "mock":
                raise LabError("mock_image_kind_mismatch")
            driver.report.add("mock.kind", "PASS", "no_official_client_or_package_context")
            # The probe image needs packages; follow the same validated build
            # network as the runtime image instead of silently using whatever the
            # host daemon defaults to (a transparent proxy breaks DNS here).
            build_network = os.environ.get("BUILD_NETWORK", "default")
            probe_cmd = ["docker", "--host", driver.docker_host, "build",
                         "--file", str(driver.root / "tests/Dockerfile.probe"),
                         "--tag", lab.probe]
            if build_network == "host":
                probe_cmd += ["--network", "host"]
            probe_cmd.append(str(driver.root / "tests"))
            driver.call(probe_cmd, timeout=900)
            lab.certificates()
        else:
            if not args.image:
                raise LabError("client_requires_explicit_official_image")
            metadata = driver.inspect(lab.image, "image")
            if metadata.get("Config", {}).get("Labels", {}).get("io.feilian.client.kind") != "official":
                raise LabError("client_requires_official_image")
        lab.setup_networks()
        if suite == "mock":
            lab.service("bootstrap", ("NET_BIND_SERVICE",))
            lab.service("relay", ("NET_ADMIN", "NET_BIND_SERVICE"))
            driver.docker("cp", str(lab.state) + "/.", lab.names["bootstrap"] + ":/labstate")
            driver.docker("start", lab.names["bootstrap"], lab.names["relay"])
        lab.app(suite)
        if suite == "mock":
            lab.mock_checks()
        else:
            lab.wait_status(False, timeout=120)
            driver.smoke_existing(lab.names["app"], lab.image)
    except Exception as error:
        detail = str(error) if re.fullmatch(r"[a-z0-9_]+", str(error)) else "integration_operation_failed"
        driver.report.add(suite + ".driver", "FAIL", detail)
    finally:
        if args.keep_on_failure and driver.report.failed:
            driver.report.add("cleanup.kept", "SKIP", "explicit_keep_on_failure_private_resources", required=False,
                              evidence={"owner": lab.owner})
        else:
            lab.cleanup()
