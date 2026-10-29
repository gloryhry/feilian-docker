#!/usr/bin/env python3
"""Restricted dotenv configuration. Never source/eval configuration or env output.

Precedence: repeated --set > recognized environment > dotenv > safe defaults.
Secret paths are validated without opening secret files. Exit 2 means invalid
configuration, and rendering produces no partial output on validation failure.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VERSION = "3.2.16"
DEFAULTS = {
    "PROJECT_NAME": "feilian", "CLIENT_MANIFEST": "config/client.lock.json",
    "IMAGE_REF": "", "NET_MODE": "bridge", "ALLOW_HOST_NETWORK": "0",
    "NOVNC_HOST_PORT": "6080", "NOVNC_INTERNAL_PORT": "6080",
    "WEB_BIND": "127.0.0.1", "WEB_AUTH": "1", "WEB_TLS": "off",
    "WEB_SOURCE_CIDRS": "", "WEB_AUTH_FILE": "", "WEB_TLS_CERT_FILE": "",
    "WEB_TLS_KEY_FILE": "", "GUI_MODE": "vnc", "VNC_GEOMETRY": "1600x1000x24",
    "X11_DISPLAY": "", "VNC_PASSWORD": "", "VNC_PASSWORD_FILE": "",
    "PROXY_ENABLED": "1", "PROXY_REQUIRE_VPN": "1", "PROXY_BIND": "127.0.0.1",
    "HTTP_PROXY_HOST_PORT": "8888", "HTTP_PROXY_INTERNAL_PORT": "8118",
    "SOCKS_PROXY_HOST_PORT": "1088", "SOCKS_PROXY_INTERNAL_PORT": "1080",
    "PROXY_SOURCE_CIDRS": "", "PROXY_CONNECT_PORTS": "443",
    "CORP_DOMAINS": "", "CORP_CIDRS": "", "DNS_MODE": "auto",
    "VPN_DNS_SOURCE": "file", "VPN_DNS": "",
    "VPN_CONFIG_FILE": "/opt/apps/com.volcengine.feilian/files/vpn.conf",
    "VPN_IFACE": "auto", "VPN_PROBE_DNS_NAME": "", "VPN_PROBE_URL": "",
    "VPN_PROBE_EXPECT_STATUS": "200", "VPN_PROBE_CA_FILE": "",
    "GATEWAY_ENABLED": "0", "GATEWAY_SOURCE_CIDRS": "", "ACCESS_SUBNET": "",
    "GATEWAY_IP": "", "MSS_MODE": "off", "GUARD_ENABLED": "1",
    "START_NETWORKMANAGER": "1", "START_SERVICE": "1", "START_GUI": "1",
    "MACVLAN_PARENT": "", "MACVLAN_SUBNET": "", "MACVLAN_GATEWAY": "",
    "MACVLAN_IP": "", "MACVLAN_SHIM": "0", "MACVLAN_SHIM_IP": "",
    "BUILD_PLATFORMS": "native", "BUILD_OUTPUT": "load", "BUILD_NETWORK": "default",
    "DEBIAN_MIRROR": "", "NO_CACHE": "0",
    "REGISTRY_IMAGE": "ghcr.io/gloryhry/feilian-docker", "PROBE_TIMEOUT": "8",
    "HOST_NET_APPLY": "0", "STOP_TIMEOUT": "20", "UP_IF": "",
}
ALIASES = {"TAG": "IMAGE_REF", "NOVNC_PORT": "NOVNC_HOST_PORT"}
INPUT_KEYS = frozenset(DEFAULTS) | frozenset(ALIASES)
SECRET_KEYS = frozenset({"VNC_PASSWORD"})
BOOL_KEYS = {
    "ALLOW_HOST_NETWORK", "WEB_AUTH", "PROXY_ENABLED", "PROXY_REQUIRE_VPN",
    "GATEWAY_ENABLED", "GUARD_ENABLED", "START_NETWORKMANAGER", "START_SERVICE",
    "START_GUI", "MACVLAN_SHIM", "NO_CACHE", "HOST_NET_APPLY",
}
PORT_KEYS = {
    "NOVNC_HOST_PORT", "NOVNC_INTERNAL_PORT", "HTTP_PROXY_HOST_PORT",
    "HTTP_PROXY_INTERNAL_PORT", "SOCKS_PROXY_HOST_PORT", "SOCKS_PROXY_INTERNAL_PORT",
}
ENUMS = {
    "NET_MODE": {"bridge", "auto", "host", "macvlan"}, "GUI_MODE": {"vnc", "x11"},
    "WEB_TLS": {"off", "selfsigned", "provided"},
    "DNS_MODE": {"auto", "full", "split", "off"}, "VPN_DNS_SOURCE": {"file", "manual"},
    "BUILD_OUTPUT": {"load", "oci", "push"}, "BUILD_NETWORK": {"default", "host"},
}
UNSAFE = re.compile(r"[\x00-\x20\x7f$`\\;|&<>\"']")
PATH_RE = re.compile(r"^[A-Za-z0-9_./+@-]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}$")
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._-]*(?::[0-9]+)?/)*[a-z0-9][a-z0-9._-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$")


class ConfigError(ValueError):
    """Invalid configuration; never include rejected values in errors."""


def _safe(key, value):
    if key not in INPUT_KEYS:
        raise ConfigError("unknown configuration key")
    if not isinstance(value, str):
        raise ConfigError("configuration values must be strings")
    if key in SECRET_KEYS and value:
        raise ConfigError("VNC_PASSWORD is no longer accepted; migrate to VNC_PASSWORD_FILE")
    if len(value) > 8192 or UNSAFE.search(value):
        raise ConfigError("{} contains forbidden syntax or whitespace".format(key))
    return value


def parse_dotenv(text):
    """Allow literal KEY=VALUE, matching outer quotes, and full-line comments."""
    result = {}
    for number, raw in enumerate(text.split("\n"), 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        if "\r" in raw:
            raise ConfigError("config line {} has a control character".format(number))
        line = raw.strip(" \t")
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError("config line {} must be KEY=VALUE".format(number))
        key, value = (part.strip(" \t") for part in line.split("=", 1))
        if key not in INPUT_KEYS:
            raise ConfigError("config line {} has an unknown key".format(number))
        if key in result:
            raise ConfigError("duplicate configuration key {}".format(key))
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ConfigError("config line {} has unmatched quotes".format(number))
            value = value[1:-1]
        result[key] = _safe(key, value)
    return result


def _read_config(path, missing_ok):
    try:
        with path.open("rb") as handle:
            content = handle.read(128 * 1024 + 1)
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise ConfigError("configuration file does not exist") from None
    except OSError:
        raise ConfigError("cannot read configuration file") from None
    if len(content) > 128 * 1024:
        raise ConfigError("configuration file exceeds size limit")
    try:
        return parse_dotenv(content.decode("utf-8"))
    except UnicodeError:
        raise ConfigError("configuration file must be UTF-8") from None


def _canonical(values):
    result = {}
    for key, raw in values.items():
        value = _safe(key, raw)
        target = ALIASES.get(key, key)
        if target in result and result[target] != value:
            raise ConfigError("conflicting alias for {}".format(target))
        result[target] = value
    return result


def _overrides(items):
    result = {}
    for item in items:
        if "=" not in item:
            raise ConfigError("--set requires KEY=VALUE")
        key, value = item.split("=", 1)
        if key in result:
            raise ConfigError("duplicate --set configuration key")
        result[key] = _safe(key, value)
    return result


def _image_default(root, name):
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    try:
        with path.open("rb") as handle:
            content = handle.read(1024 * 1024 + 1)
    except FileNotFoundError:
        return "feilian-gui:" + DEFAULT_VERSION + "-wrapper-dev"
    except OSError:
        raise ConfigError("cannot read CLIENT_MANIFEST") from None
    if len(content) > 1024 * 1024:
        raise ConfigError("CLIENT_MANIFEST exceeds size limit")
    try:
        manifest = json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise ConfigError("CLIENT_MANIFEST must contain valid UTF-8 JSON") from None
    if (not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1 or not isinstance(manifest.get("release"), dict)):
        raise ConfigError("CLIENT_MANIFEST requires schema_version=1 and release.version")
    version = manifest["release"].get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9_.-]+)?", version):
        raise ConfigError("CLIENT_MANIFEST has an invalid release.version")
    return "feilian-gui:" + version.replace("+", "-") + "-wrapper-dev"


def _integer(key, value, low, high):
    if not re.fullmatch(r"[0-9]{1,8}", value) or not low <= int(value) <= high:
        raise ConfigError("{} must be a decimal integer in range {}..{}".format(key, low, high))
    return str(int(value))


def _list(key, value):
    if not value:
        return []
    parts = value.split(",")
    if any(not part for part in parts) or len(parts) > 256 or len(set(parts)) != len(parts):
        raise ConfigError("{} requires a unique comma-separated list".format(key))
    return parts


def _ip(key, value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ConfigError("{} must be an IP address, not a hostname".format(key)) from None
    if address.is_multicast:
        raise ConfigError("{} must not be multicast".format(key))
    return address


def _network(key, value):
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ConfigError("{} must be a canonical CIDR".format(key)) from None
    if net.prefixlen == 0 or net.is_multicast or net.is_unspecified:
        raise ConfigError("{} must not be a default/unspecified network".format(key))
    return net


def _cidrs(key, value):
    nets = [_network(key, item) for item in _list(key, value)]
    for index, first in enumerate(nets):
        for second in nets[index + 1:]:
            if first.version == second.version and first.overlaps(second):
                raise ConfigError("{} contains overlapping CIDRs".format(key))
    return nets


def _domain(key, value):
    value = value.lower().rstrip(".")
    if not value or len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ConfigError("{} requires literal DNS names without wildcards".format(key))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ConfigError("{} requires DNS names, not IP addresses".format(key))


def _url(key, value):
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ConfigError("{} must be a valid HTTP(S) URL".format(key)) from None
    if (parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.fragment or (port is not None and not 1 <= port <= 65535)):
        raise ConfigError("{} requires HTTP(S), a host and no credentials/fragment".format(key))
    if key == "VPN_PROBE_URL" and parts.scheme != "https":
        raise ConfigError("VPN_PROBE_URL requires HTTPS; TLS verification cannot be disabled")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        _domain(key, parts.hostname)
    else:
        if address.is_unspecified or address.is_multicast:
            raise ConfigError("{} must name a unicast host".format(key))


def _loopback(address):
    return (getattr(address, "ipv4_mapped", None) or address).is_loopback


def _host(key, address, subnet):
    if (address.version != subnet.version or address not in subnet or address.is_unspecified
            or address.is_multicast or (subnet.version == 4 and subnet.prefixlen <= 30
                and address in {subnet.network_address, subnet.broadcast_address})):
        raise ConfigError("{} must be a usable host inside its subnet".format(key))


def _no_overlap(left, right, message):
    if any(a.version == b.version and a.overlaps(b) for a in left for b in right):
        raise ConfigError(message)


def _validate(c, explicit):
    for key, choices in ENUMS.items():
        if c[key] not in choices:
            raise ConfigError("{} has an unsupported value".format(key))
    for key in BOOL_KEYS:
        if c[key] not in {"0", "1"}:
            raise ConfigError("{} must be 0 or 1".format(key))
    for key in PORT_KEYS:
        c[key] = _integer(key, c[key], 1, 65535)
    for key, low, high in (("PROBE_TIMEOUT", 1, 300), ("STOP_TIMEOUT", 1, 600), ("VPN_PROBE_EXPECT_STATUS", 100, 599)):
        c[key] = _integer(key, c[key], low, high)
    for key in DEFAULTS:
        if key.endswith("_FILE") or key == "CLIENT_MANIFEST":
            if c[key] and (not PATH_RE.fullmatch(c[key]) or c[key].endswith("/")):
                raise ConfigError("{} requires a literal file path".format(key))
    if not c["CLIENT_MANIFEST"] or not c["VPN_CONFIG_FILE"]:
        raise ConfigError("CLIENT_MANIFEST and VPN_CONFIG_FILE must not be empty")
    if c["VPN_PROBE_CA_FILE"] and not Path(c["VPN_PROBE_CA_FILE"]).is_absolute():
        raise ConfigError("VPN_PROBE_CA_FILE requires an absolute file path")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", c["PROJECT_NAME"]):
        raise ConfigError("PROJECT_NAME requires a safe Compose project name")
    for key in ("IMAGE_REF", "REGISTRY_IMAGE"):
        if not IMAGE_RE.fullmatch(c[key]):
            raise ConfigError("{} requires a Docker image reference".format(key))
    geometry = re.fullmatch(r"([0-9]{2,5})x([0-9]{2,5})x(16|24|32)", c["VNC_GEOMETRY"])
    if not geometry or not 320 <= int(geometry[1]) <= 16384 or not 200 <= int(geometry[2]) <= 16384:
        raise ConfigError("VNC_GEOMETRY requires bounded width x height x depth (16/24/32)")
    if c["X11_DISPLAY"] and not re.fullmatch(r":[0-9]{1,3}(?:\.[0-9]{1,2})?", c["X11_DISPLAY"]):
        raise ConfigError("X11_DISPLAY requires a local X socket")
    if c["GUI_MODE"] == "x11" and c["START_GUI"] == "1" and not c["X11_DISPLAY"]:
        raise ConfigError("GUI_MODE=x11 requires X11_DISPLAY")
    for key in ("VPN_IFACE", "MACVLAN_PARENT", "UP_IF"):
        if c[key] and not IFACE_RE.fullmatch(c[key]):
            raise ConfigError("{} requires a literal Linux interface name".format(key))
    if not c["VPN_IFACE"]:
        raise ConfigError("VPN_IFACE must be auto or an interface name")
    nets = {key: _cidrs(key, c[key]) for key in ("WEB_SOURCE_CIDRS", "PROXY_SOURCE_CIDRS", "CORP_CIDRS", "GATEWAY_SOURCE_CIDRS")}
    for key, values in nets.items():
        c[key] = ",".join(str(net) for net in values)
    domains = [_domain("CORP_DOMAINS", item.lstrip(".")) for item in _list("CORP_DOMAINS", c["CORP_DOMAINS"])]
    if len(set(domains)) != len(domains):
        raise ConfigError("CORP_DOMAINS contains duplicate normalized names")
    c["CORP_DOMAINS"] = ",".join(domains)
    if c["VPN_PROBE_DNS_NAME"]:
        c["VPN_PROBE_DNS_NAME"] = _domain("VPN_PROBE_DNS_NAME", c["VPN_PROBE_DNS_NAME"])
    for key in ("VPN_PROBE_URL", "DEBIAN_MIRROR"):
        if c[key]:
            _url(key, c[key])
    dns = [_ip("VPN_DNS", item) for item in _list("VPN_DNS", c["VPN_DNS"])]
    if any(item.is_unspecified for item in dns) or len(set(dns)) != len(dns):
        raise ConfigError("VPN_DNS requires unique unicast DNS addresses")
    c["VPN_DNS"] = ",".join(str(item) for item in dns)
    ports = [_integer("PROXY_CONNECT_PORTS", item, 1, 65535) for item in _list("PROXY_CONNECT_PORTS", c["PROXY_CONNECT_PORTS"])]
    if not ports or len(set(ports)) != len(ports):
        raise ConfigError("PROXY_CONNECT_PORTS requires a nonempty unique port list")
    c["PROXY_CONNECT_PORTS"] = ",".join(ports)
    if c["MSS_MODE"] not in {"off", "auto"}:
        c["MSS_MODE"] = _integer("MSS_MODE", c["MSS_MODE"], 536, 8960)
    platforms = _list("BUILD_PLATFORMS", c["BUILD_PLATFORMS"])
    if not platforms or any(item not in {"native", "linux/amd64", "linux/arm64"} for item in platforms):
        raise ConfigError("BUILD_PLATFORMS requires native or supported Linux platforms")
    if len(platforms) > 1 and ("native" in platforms or c["BUILD_OUTPUT"] == "load"):
        raise ConfigError("multiple explicit BUILD_PLATFORMS require oci or push output")
    if c["WEB_TLS"] == "provided" and not (c["WEB_TLS_CERT_FILE"] and c["WEB_TLS_KEY_FILE"]):
        raise ConfigError("WEB_TLS=provided requires WEB_TLS_CERT_FILE and WEB_TLS_KEY_FILE")
    web, proxy = _ip("WEB_BIND", c["WEB_BIND"]), _ip("PROXY_BIND", c["PROXY_BIND"])
    if not _loopback(proxy):
        raise ConfigError("raw proxy LAN exposure is forbidden; PROXY_BIND must be loopback")
    if not _loopback(web) and not (c["WEB_AUTH"] == "1" and c["WEB_TLS"] != "off" and nets["WEB_SOURCE_CIDRS"]):
        raise ConfigError("non-loopback WEB_BIND requires authentication, TLS and WEB_SOURCE_CIDRS")
    if c["NET_MODE"] == "auto":
        c["NET_MODE"] = "bridge"  # Never fall back to host networking.
    if c["NET_MODE"] == "host":
        if c["ALLOW_HOST_NETWORK"] != "1":
            raise ConfigError("NET_MODE=host requires ALLOW_HOST_NETWORK=1")
        if not _loopback(web):
            raise ConfigError("host mode requires a loopback WEB_BIND")
        for key, safe in (("PROXY_ENABLED", "0"), ("DNS_MODE", "off"), ("GUARD_ENABLED", "0"), ("START_NETWORKMANAGER", "0")):
            if key not in explicit:
                c[key] = safe
        if (c["PROXY_ENABLED"] != "0" or c["GATEWAY_ENABLED"] != "0" or c["MSS_MODE"] != "off"
                or c["GUARD_ENABLED"] != "0" or c["DNS_MODE"] != "off" or c["START_NETWORKMANAGER"] != "0"):
            raise ConfigError("host mode forbids managed proxy, gateway, MSS, guard, DNS and NetworkManager")
    if c["PROXY_ENABLED"] == "1" and (c["PROXY_REQUIRE_VPN"] != "1" or c["GUARD_ENABLED"] != "1"):
        raise ConfigError("proxy requires PROXY_REQUIRE_VPN=1 and GUARD_ENABLED=1")
    if c["GATEWAY_ENABLED"] == "1" and c["GUARD_ENABLED"] != "1":
        raise ConfigError("gateway requires GUARD_ENABLED=1")
    if c["MSS_MODE"] != "off" and c["GATEWAY_ENABLED"] != "1":
        raise ConfigError("MSS requires GATEWAY_ENABLED=1")
    access = _network("ACCESS_SUBNET", c["ACCESS_SUBNET"]) if c["ACCESS_SUBNET"] else None
    gateway = _ip("GATEWAY_IP", c["GATEWAY_IP"]) if c["GATEWAY_IP"] else None
    if (access is not None and access.version != 4) or (gateway is not None and gateway.version != 4):
        raise ConfigError("ACCESS_SUBNET and GATEWAY_IP currently require IPv4")
    if access is not None and gateway is not None:
        _host("GATEWAY_IP", gateway, access)
    if c["GATEWAY_ENABLED"] == "1":
        if not nets["GATEWAY_SOURCE_CIDRS"] or not nets["CORP_CIDRS"] or access is None or gateway is None:
            raise ConfigError("gateway requires source CIDRs, CORP_CIDRS, ACCESS_SUBNET and GATEWAY_IP")
        _no_overlap(nets["GATEWAY_SOURCE_CIDRS"], nets["CORP_CIDRS"], "gateway source and corporate CIDRs must not overlap")
        _no_overlap([access], nets["CORP_CIDRS"], "ACCESS_SUBNET and corporate CIDRs must not overlap")
        if any(source.version != 4 or not source.subnet_of(access) for source in nets["GATEWAY_SOURCE_CIDRS"]):
            raise ConfigError("each GATEWAY_SOURCE_CIDRS entry must be inside ACCESS_SUBNET")
    subnet = _network("MACVLAN_SUBNET", c["MACVLAN_SUBNET"]) if c["MACVLAN_SUBNET"] else None
    if subnet is not None and subnet.version != 4:
        raise ConfigError("MACVLAN_SUBNET currently requires IPv4")
    addresses = {}
    for key in ("MACVLAN_GATEWAY", "MACVLAN_IP", "MACVLAN_SHIM_IP"):
        if c[key]:
            addresses[key] = _ip(key, c[key])
            if addresses[key].version != 4:
                raise ConfigError("macvlan addresses currently require IPv4")
            if subnet is not None:
                _host(key, addresses[key], subnet)
    if len(set(addresses.values())) != len(addresses):
        raise ConfigError("macvlan gateway, container and shim IPs must differ")
    if c["NET_MODE"] == "macvlan":
        if not c["MACVLAN_PARENT"] or subnet is None or not all(key in addresses for key in ("MACVLAN_GATEWAY", "MACVLAN_IP")):
            raise ConfigError("macvlan requires parent, subnet, gateway and container IP")
        if c["WEB_TLS"] == "off" or c["WEB_AUTH"] != "1" or not nets["WEB_SOURCE_CIDRS"]:
            raise ConfigError("macvlan requires WEB_TLS, WEB_AUTH=1 and WEB_SOURCE_CIDRS")
    if c["MACVLAN_SHIM"] == "1" and (c["NET_MODE"] != "macvlan" or "MACVLAN_SHIM_IP" not in addresses):
        raise ConfigError("MACVLAN_SHIM requires macvlan mode and an explicit shim IP")
    if c["PROXY_ENABLED"] == "1":
        host_ports = [c["HTTP_PROXY_HOST_PORT"], c["SOCKS_PROXY_HOST_PORT"]]
        internal_ports = [c["HTTP_PROXY_INTERNAL_PORT"], c["SOCKS_PROXY_INTERNAL_PORT"]]
        if c["GUI_MODE"] == "vnc":
            host_ports.append(c["NOVNC_HOST_PORT"])
            internal_ports.append(c["NOVNC_INTERNAL_PORT"])
        if len(set(host_ports)) != len(host_ports) or len(set(internal_ports)) != len(internal_ports):
            raise ConfigError("enabled proxy and web ports must not collide")
    c["TAG"], c["NOVNC_PORT"] = c["IMAGE_REF"], c["NOVNC_HOST_PORT"]
    configured = bool((c["CORP_DOMAINS"] or c["CORP_CIDRS"]) and (c["VPN_PROBE_DNS_NAME"] or c["VPN_PROBE_URL"]))
    c["FEILIAN_CONFIG_STATUS"] = "CONFIGURED" if configured else "UNCONFIGURED"


def load_config(config_path=None, environ=None, overrides=(), project_root=None):
    """Return validated strings. Only an omitted project-root .env may be absent."""
    root = Path(project_root) if project_root is not None else ROOT
    path = root / ".env" if config_path is None else Path(config_path)
    env = os.environ if environ is None else environ
    layers = (_canonical(_read_config(path, config_path is None)),
              _canonical({key: env[key] for key in INPUT_KEYS if key in env}),
              _canonical(_overrides(overrides)))
    c, explicit = dict(DEFAULTS), set()
    for layer in layers:
        c.update(layer)
        explicit.update(layer)
    name = c["CLIENT_MANIFEST"]
    if not name or not PATH_RE.fullmatch(name) or name.endswith("/"):
        raise ConfigError("CLIENT_MANIFEST requires a literal file path")
    if "IMAGE_REF" not in explicit:
        c["IMAGE_REF"] = _image_default(root, name)
    _validate(c, explicit)
    return c


def render_env(config):
    allowed = (INPUT_KEYS | {"FEILIAN_CONFIG_STATUS"}) - SECRET_KEYS
    return "".join("{}={}\n".format(key, config[key]) for key in sorted(allowed))


def render_json(config):
    allowed = INPUT_KEYS | {"FEILIAN_CONFIG_STATUS"}
    safe = {key: "<redacted>" if key in SECRET_KEYS else config[key] for key in sorted(allowed)}
    return json.dumps(safe, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "render"))
    parser.add_argument("--config", metavar="FILE")
    parser.add_argument("--format", choices=("env", "json"), default="env")
    parser.add_argument("--set", dest="overrides", action="append", default=[], metavar="KEY=VALUE")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, overrides=args.overrides)
    except ConfigError as error:
        print("feilian config: {}".format(error), file=sys.stderr)
        return 2
    if args.command == "render":
        sys.stdout.write(render_json(config) if args.format == "json" else render_env(config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
