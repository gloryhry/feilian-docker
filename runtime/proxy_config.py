#!/usr/bin/env python3
"""Closed-by-default, non-root Privoxy -> microsocks configuration (no daemon calls).

The controller must stop old proxy processes and close the guard before preparing
new configurations. READY is evidence supplied by the VPN controller, not inferred
from DNS, route discovery, a process, or an existing configuration file here.

Dante is not packaged for Debian trixie, so the SOCKS5 server is microsocks (also
packaged). It carries no ACL language: destination/source enforcement lives in the
packet-level nft guard, and microsocks is only ever started with an explicit
loopback/allowlisted listener and `-b <VPN IPv4>` so outbound sockets never fall
back to the bootstrap interface.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

SOCKS_UID = 1001
HTTP_UID = 1002
SOCKS_USER = "feilian-socks"
HTTP_USER = "feilian-http"
MAX_CONTEXT = 128 * 1024
BACKEND_PORTS = (31055, 31056)
FIXED_DENY = (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "100.100.100.200/32", "168.63.129.16/32",
)
DEFAULTS = {
    "ready": False, "proxy_enabled": True, "vpn_interface": "", "vpn_ipv4": [],
    "vpn_dns": [], "source_cidrs": [], "corp_cidrs": [], "management_cidrs": [],
    "access_interface": "eth0", "bridge_gateway": "", "macvlan_shim": False,
    "http_port": 8118, "socks_port": 1080, "connect_ports": [443], "gateway": {},
}
GATEWAY_DEFAULTS = {
    "enabled": False, "source_cidrs": [], "access_subnet": "", "gateway_ipv4": "", "mss": "off",
}
CONFIG_FILES = ("privoxy.conf", "microsocks.json", "feilian.action")
MICROSOCKS = "/usr/bin/microsocks"


class ProxyError(ValueError):
    """Invalid public context or unsafe configuration state (do not echo values)."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProxyError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path, limit: int = MAX_CONTEXT) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ProxyError("context/state must be a regular file")
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ProxyError("context/state exceeds size limit")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProxyError("cannot read valid public context/state JSON") from exc


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ProxyError(f"{name} must be a JSON boolean")
    return value


def _port(value: Any, name: str, high: bool = False) -> int:
    if type(value) is not int or not (1024 if high else 1) <= value <= 65535:
        raise ProxyError(f"{name} must be a bounded integer port")
    return value


def _iface(value: Any, name: str, empty: bool = False) -> str:
    if empty and value == "":
        return ""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", value):
        raise ProxyError(f"{name} must be a literal interface name")
    return value


def _address(value: Any, name: str) -> str:
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
    except ValueError as exc:
        raise ProxyError(f"{name} must contain IPv4 addresses") from exc
    if address is None or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or address.is_reserved:
        raise ProxyError(f"{name} requires ordinary unicast IPv4 addresses")
    return str(address)


def _addresses(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ProxyError(f"{name} must be a bounded IPv4 list")
    result = [_address(item, name) for item in value]
    if len(set(result)) != len(result):
        raise ProxyError(f"{name} must not repeat addresses")
    return result


def _network(value: Any, name: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True) if isinstance(value, str) else None
    except ValueError as exc:
        raise ProxyError(f"{name} requires canonical IPv4 CIDRs") from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
        raise ProxyError(f"{name} requires non-default unicast IPv4 CIDRs; IPv6 data is unsupported")
    return network


def _networks(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 128:
        raise ProxyError(f"{name} must be a bounded CIDR list")
    networks = [_network(item, name) for item in value]
    if any(first.overlaps(second) for index, first in enumerate(networks) for second in networks[index + 1:]):
        raise ProxyError(f"{name} must not contain duplicate/overlapping CIDRs")
    return [str(network) for network in networks]


def normalize_context(raw: Any) -> dict[str, Any]:
    required = {"schema_version", "project", "network_mode"}
    if not isinstance(raw, dict) or not required <= set(raw) or set(raw) - required - set(DEFAULTS):
        raise ProxyError("context requires schema/project/network_mode and known keys only")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ProxyError("schema_version must be integer 1")
    if not isinstance(raw["project"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", raw["project"]):
        raise ProxyError("project must be a safe literal project name")
    if raw["network_mode"] not in ("bridge", "macvlan", "host"):
        raise ProxyError("network_mode must be bridge, macvlan or host")
    context = dict(DEFAULTS, **raw)
    for key in ("ready", "proxy_enabled", "macvlan_shim"):
        context[key] = _bool(context[key], key)
    for key in ("vpn_ipv4", "vpn_dns"):
        context[key] = _addresses(context[key], key)
    for key in ("source_cidrs", "corp_cidrs", "management_cidrs"):
        context[key] = _networks(context[key], key)
    context["access_interface"] = _iface(context["access_interface"], "access_interface")
    if context["access_interface"] == "lo":
        raise ProxyError("access_interface must not be loopback")
    context["vpn_interface"] = _iface(context["vpn_interface"], "vpn_interface", empty=True)
    interface = context["vpn_interface"]
    if interface and (interface in ("lo", "eth0", "docker0", context["access_interface"]) or interface.startswith(("veth", "br-"))):
        raise ProxyError("VPN interface must not be loopback, access or bootstrap networking")
    if context["bridge_gateway"] != "":
        context["bridge_gateway"] = _address(context["bridge_gateway"], "bridge_gateway")
    elif not isinstance(context["bridge_gateway"], str):
        raise ProxyError("bridge_gateway must be an IPv4 string or empty")
    for key in ("http_port", "socks_port"):
        context[key] = _port(context[key], key, high=True)
    if context["http_port"] == context["socks_port"] or any(context[key] in BACKEND_PORTS for key in ("http_port", "socks_port")):
        raise ProxyError("proxy listener ports must be distinct from each other and backend ports")
    if not isinstance(context["connect_ports"], list) or not 1 <= len(context["connect_ports"]) <= 64:
        raise ProxyError("connect_ports must be a nonempty bounded integer list")
    ports = [_port(value, "connect_ports") for value in context["connect_ports"]]
    if len(set(ports)) != len(ports) or any(port in (*BACKEND_PORTS, 53) for port in ports):
        raise ProxyError("CONNECT ports must be unique and must not expose DNS/backend services")
    context["connect_ports"] = sorted(ports)
    gateway = context["gateway"]
    if not isinstance(gateway, dict) or set(gateway) - set(GATEWAY_DEFAULTS):
        raise ProxyError("gateway must contain known gateway keys only")
    gateway = dict(GATEWAY_DEFAULTS, **gateway)
    gateway["enabled"] = _bool(gateway["enabled"], "gateway.enabled")
    gateway["source_cidrs"] = _networks(gateway["source_cidrs"], "gateway.source_cidrs")
    if gateway["access_subnet"] != "":
        gateway["access_subnet"] = str(_network(gateway["access_subnet"], "gateway.access_subnet"))
    if gateway["gateway_ipv4"] != "":
        gateway["gateway_ipv4"] = _address(gateway["gateway_ipv4"], "gateway.gateway_ipv4")
    mss = gateway["mss"]
    if not ((isinstance(mss, str) and mss in ("off", "auto")) or (type(mss) is int and 536 <= mss <= 8960)):
        raise ProxyError("gateway.mss must be off, auto or an integer in 536..8960")
    if not gateway["enabled"] and mss != "off":
        raise ProxyError("MSS adjustment is only available for an explicitly enabled gateway")
    if gateway["enabled"]:
        if not gateway["source_cidrs"] or not gateway["access_subnet"] or not gateway["gateway_ipv4"] or not context["corp_cidrs"]:
            raise ProxyError("gateway requires sources, access subnet/address and corporate CIDRs")
        access = ipaddress.IPv4Network(gateway["access_subnet"])
        address = ipaddress.IPv4Address(gateway["gateway_ipv4"])
        if address not in access or (access.prefixlen <= 30 and address in (access.network_address, access.broadcast_address)):
            raise ProxyError("gateway address must be a usable host within access_subnet")
        if any(not ipaddress.IPv4Network(source).subnet_of(access) for source in gateway["source_cidrs"]):
            raise ProxyError("gateway sources must be inside access_subnet")
        if any(access.overlaps(ipaddress.IPv4Network(corp)) for corp in context["corp_cidrs"]):
            raise ProxyError("gateway access/source and corporate networks must not overlap")
    context["gateway"] = gateway
    missing = [name for name in ("vpn_interface", "vpn_ipv4", "vpn_dns", "corp_cidrs") if not context[name]]
    if context["network_mode"] == "host":
        ready, reason = False, "HOST_MODE_FORBIDDEN"
    elif not context["ready"]:
        ready, reason = False, "VPN_NOT_READY"
    elif missing:
        ready, reason = False, "MISSING_VPN_EVIDENCE"
    else:
        ready, reason = True, "VPN_READY"
    context["effective_ready"], context["reason"] = ready, reason
    context["proxy_ready"] = ready and context["proxy_enabled"]
    sources = ["127.0.0.1/32"]
    if context["network_mode"] == "macvlan" and not context["macvlan_shim"]:
        listen = "127.0.0.1"
    else:
        listen = "0.0.0.0"
        sources += context["source_cidrs"]
        if not context["source_cidrs"] and context["network_mode"] == "bridge" and context["bridge_gateway"]:
            sources.append(context["bridge_gateway"] + "/32")
    context["proxy_sources"] = [str(net) for net in ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in sources)]
    # Ordinary HTTP/80 is intentional; HTTP CONNECT still uses connect_ports only.
    context["data_ports"] = sorted({80, *context["connect_ports"]})
    if len(context["proxy_sources"]) * len(context["corp_cidrs"]) * len(context["data_ports"]) > 4096:
        raise ProxyError("proxy ACL expansion exceeds rule limit")
    context["listen_ipv4"] = listen
    denies = list(FIXED_DENY) + context["management_cidrs"] + [address + "/32" for address in context["vpn_ipv4"]]
    for address in (context["bridge_gateway"], gateway["gateway_ipv4"]):
        if address:
            denies.append(address + "/32")
    context["denied_targets"] = [str(net) for net in ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in denies)]
    return context


def load_context(path: Path) -> dict[str, Any]:
    return normalize_context(read_json(path))


def _safe_path(path: Path, file: bool = False) -> None:
    if not path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[A-Za-z0-9_./-]+", str(path)):
        raise ProxyError("state directory must be an absolute literal path without traversal")
    for index in range(1, len(path.parts) + 1):
        current = Path(*path.parts[:index])
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ProxyError("refusing symlink in proxy state path")
        expected = stat.S_ISREG if file and index == len(path.parts) else stat.S_ISDIR
        if not expected(info.st_mode):
            raise ProxyError("unexpected proxy state path type")


def render_configs(context: dict[str, Any], state_dir: Path = Path("/run/feilian")) -> dict[str, Any]:
    _safe_path(state_dir)
    result = {
        "schema_version": 1, "project": context["project"],
        "status": "READY" if context["proxy_ready"] else "CLOSED", "effective_ready": context["proxy_ready"],
        "reason": context["reason"] if context["proxy_enabled"] else "PROXY_DISABLED",
        "listen_ipv4": context["listen_ipv4"], "source_cidrs": context["proxy_sources"],
        "external_ipv4": context["vpn_ipv4"][0] if context["proxy_ready"] else None,
        "data_ports": context["data_ports"], "denied_targets": context["denied_targets"],
        "corp_cidrs": context["corp_cidrs"], "vpn_interface": context["vpn_interface"],
        "daemon_uids": {"socks": SOCKS_UID, "http": HTTP_UID}, "files": {},
    }
    if not context["proxy_ready"]:
        return result
    sources, corp = context["proxy_sources"], context["corp_cidrs"]
    header = f"# project={context['project']} schema=1; nonsecret; generated, do not edit"
    privoxy = [
        header, f"listen-address {context['listen_ipv4']}:{context['http_port']}",
        "toggle 1", "enable-remote-toggle 0", "enable-remote-http-toggle 0", "enable-edit-actions 0",
        "enforce-blocks 1", "accept-intercepted-requests 0", "debug 0",
        # Privoxy matches access rules first-to-last: permits MUST precede the
        # catch-all deny, otherwise every client (including loopback) is refused.
        *[f"permit-access {source}" for source in sources], "deny-access 0.0.0.0/0",
        f"actionsfile {state_dir / 'proxy' / 'feilian.action'}",
        f"forward-socks5t / 127.0.0.1:{context['socks_port']} .",
    ]
    socks_spec = {
        "uid": SOCKS_UID, "gid": SOCKS_UID, "user": SOCKS_USER,
        # -b pins outbound source to the current VPN address; -q keeps stdout quiet.
        "argv": [MICROSOCKS, "-q", "-i", context["listen_ipv4"],
                 "-p", str(context["socks_port"]), "-b", context["vpn_ipv4"][0]],
        "listen_ipv4": context["listen_ipv4"], "listen_port": context["socks_port"],
        "bound_source_ipv4": context["vpn_ipv4"][0],
        # No user/pass is configured: only the guard-enforced source ACL and the
        # loopback/allowlisted listener gate access. Never bind 0.0.0.0 in macvlan.
        "auth": "none-source-acl-required",
        "acl_owner": "nft-guard",
    }
    actions = header + "\n{+limit-connect{" + ",".join(map(str, context["connect_ports"])) + "}}\n/\n"
    result["files"] = {
        "privoxy.conf": "\n".join(privoxy) + "\n",
        "microsocks.json": json.dumps(socks_spec, indent=2, sort_keys=True) + "\n",
        "feilian.action": actions,
    }
    return result


def _atomic(path: Path, text: str) -> None:
    _safe_path(path, file=True)
    fd, name = tempfile.mkstemp(prefix=".proxy-", suffix=".part", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        _safe_path(temporary, file=True)
        _safe_path(path, file=True)
        os.replace(temporary, path)
    finally:
        _safe_path(temporary, file=True)
        temporary.unlink(missing_ok=True)


def prepare(context: dict[str, Any], state_dir: Path) -> dict[str, Any]:
    if context["network_mode"] == "host":
        raise ProxyError("proxy preparation is forbidden in host mode")
    result = render_configs(context, state_dir)
    directory = state_dir / "proxy"
    _safe_path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    _safe_path(directory)
    owner_path = directory / "status.json"
    _safe_path(owner_path, file=True)
    if owner_path.exists():
        owner = read_json(owner_path)
        if not isinstance(owner, dict) or owner.get("schema_version") != 1 or owner.get("project") != context["project"]:
            raise ProxyError("proxy state ownership conflict")
    elif any((directory / name).exists() or (directory / name).is_symlink() for name in CONFIG_FILES):
        raise ProxyError("refusing unowned existing proxy configuration")
    metadata = {key: value for key, value in result.items() if key != "files"}
    metadata["paths"] = {}
    # Publish CLOSED first: partial writes can never commit READY metadata.
    closed = dict(metadata, status="CLOSED", effective_ready=False)
    _atomic(owner_path, json.dumps(closed, sort_keys=True) + "\n")
    try:
        for name in CONFIG_FILES:
            path = directory / name
            _safe_path(path, file=True)
            if name in result["files"]:
                _atomic(path, result["files"][name])
                metadata["paths"][name] = str(path)
            else:
                path.unlink(missing_ok=True)
        _atomic(owner_path, json.dumps(metadata, sort_keys=True) + "\n")
    except Exception:
        for name in CONFIG_FILES:
            path = directory / name
            _safe_path(path, file=True)
            path.unlink(missing_ok=True)
        raise
    return metadata


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("render", "prepare"))
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, default=Path("/run/feilian"))
    args = parser.parse_args(argv)
    try:
        context = load_context(args.context)
        result = render_configs(context, args.state_dir) if args.command == "render" else prepare(context, args.state_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ProxyError, OSError) as exc:
        print(f"proxy config: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
