#!/usr/bin/env python3
"""Render/manage only the owned container inet feilian_guard nftables table.

No routes, sysctls, other tables, or daemon privileges are changed. Kernel rules
are validated as one batch and replaced in one atomic transaction. Render and
--dry-run never invoke nft; their plans explicitly do not attest kernel ownership
or syntax. Runtime integration must stop proxies before closing/reconfiguration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

if __package__:
    from .proxy_config import HTTP_UID, SOCKS_UID, BACKEND_PORTS, ProxyError, load_context
else:
    from proxy_config import HTTP_UID, SOCKS_UID, BACKEND_PORTS, ProxyError, load_context

TABLE = "feilian_guard"
FAMILY = "inet"


class PolicyError(ValueError):
    """Unsafe ownership or failed nft transaction; no unsafe fallback is allowed."""


def owner_comment(context: dict[str, Any]) -> str:
    return f"feilian_guard owner={context['project']} schema=1"


def _set(name: str, values: list, kind: str = "ipv4_addr", interval: bool = True) -> str:
    flags = " flags interval;" if interval else ""
    elements = " elements = { " + ", ".join(map(str, values)) + " };" if values else ""
    return f"  set {name} {{ type {kind};{flags}{elements} }}"


def render_policy(context: dict[str, Any], *, exists: bool = False, closed: bool = False) -> dict[str, Any]:
    owner = owner_comment(context)
    base = {
        "schema_version": 1, "project": context["project"], "family": FAMILY, "table": TABLE,
        "owner": owner, "ownership_checked": False, "kernel_syntax_checked": False,
    }
    if context["network_mode"] == "host":
        return dict(base, status="CLOSED", effective_ready=False, reason="HOST_MODE_FORBIDDEN", nft="")
    proxy_ready = context["proxy_ready"] and not closed
    gateway_ready = context["effective_ready"] and context["gateway"]["enabled"] and not closed
    uid_set = f"{{ {SOCKS_UID}, {HTTP_UID} }}"
    proxy_ports = f"{{ {context['http_port']}, {context['socks_port']} }}"
    access, vpn = context["access_interface"], context["vpn_interface"]
    lines = [f"delete table {FAMILY} {TABLE}"] if exists else []
    lines += [
        f"table {FAMILY} {TABLE} {{", f'  comment "{owner}"',
        _set("proxy_sources", context["proxy_sources"]),
        _set("corp_targets", context["corp_cidrs"]),
        _set("blocked_targets", context["denied_targets"]),
        _set("vpn_addresses", context["vpn_ipv4"], interval=False),
        _set("data_ports", context["data_ports"], "inet_service", interval=False),
        _set("gateway_sources", context["gateway"]["source_cidrs"]),
        "  chain input_guard {", "    type filter hook input priority -10; policy accept;",
        f"    meta nfproto ipv6 tcp dport {proxy_ports} reject with tcp reset",
        f"    udp dport {proxy_ports} reject with icmpx type admin-prohibited",
    ]
    if proxy_ready:
        lines.append(f"    ip saddr @proxy_sources tcp dport {proxy_ports} ct state {{ new, established }} accept")
    lines += [f"    tcp dport {proxy_ports} reject with tcp reset", "  }", "  chain output_guard {", "    type filter hook output priority -10; policy accept;"]
    # No unconditional established/related accept: every original data packet,
    # including an old TCP socket, must still satisfy the current VPN oif/CIDR.
    lines.append(f"    meta skuid {uid_set} meta nfproto ipv6 drop")
    if proxy_ready:
        for uid, port in ((HTTP_UID, context["http_port"]), (SOCKS_UID, context["socks_port"])):
            lines.append(
                f'    meta skuid {uid} oifname {{ "lo", "{access}" }} ip daddr @proxy_sources '
                f'tcp sport {port} ct direction reply ct state established accept'
            )
        lines += [
            f'    meta skuid {HTTP_UID} oifname "lo" ip daddr 127.0.0.1 tcp dport {context["socks_port"]} ct state {{ new, established }} accept',
            f'    meta skuid {SOCKS_UID} oifname "lo" ip daddr 127.0.0.1 udp dport 53 ct state {{ new, established }} accept',
            f'    meta skuid {SOCKS_UID} oifname "lo" ip daddr 127.0.0.1 tcp dport 53 ct state {{ new, established }} accept',
            f"    meta skuid {uid_set} tcp dport {{ {', '.join(map(str, BACKEND_PORTS))} }} drop",
            f"    meta skuid {uid_set} ip daddr @blocked_targets drop",
            f'    meta skuid {SOCKS_UID} oifname "{vpn}" ip saddr @vpn_addresses ip daddr @corp_targets '
            'tcp dport @data_ports ct direction original ct state { new, established } accept',
        ]
    lines += [
        f"    meta skuid {uid_set} drop", "  }", "  chain forward_guard {",
        "    type filter hook forward priority -10; policy accept;",
        f'    iifname "{access}" meta nfproto ipv6 drop',
        f'    oifname "{access}" meta nfproto ipv6 drop',
    ]
    if gateway_ready:
        lines += [
            f'    iifname "{access}" ip daddr @blocked_targets drop',
            f'    oifname "{access}" ip saddr @blocked_targets drop',
            f'    iifname "{access}" oifname "{vpn}" ip saddr @gateway_sources ip daddr @corp_targets '
            'ct direction original ct state { new, established } accept',
            f'    iifname "{vpn}" oifname "{access}" ip saddr @corp_targets ip daddr @gateway_sources '
            'ct direction reply ct state { established, related } accept',
        ]
    # Even after an earlier enabled generation, disabled/closed gateway traffic
    # cannot use a stale ip_forward setting or stale conntrack/NAT on eth0.
    lines += [
        f'    iifname "{access}" reject with icmpx type admin-prohibited',
        f'    oifname "{access}" reject with icmpx type admin-prohibited', "  }",
    ]
    if gateway_ready:
        lines += [
            "  chain gateway_snat {", "    type nat hook postrouting priority 100; policy accept;",
            f'    iifname "{access}" oifname "{vpn}" ip saddr @gateway_sources ip daddr @corp_targets '
            f'snat ip to {context["vpn_ipv4"][0]}', "  }",
        ]
        mss = context["gateway"]["mss"]
        if mss != "off":
            expression = "rt mtu" if mss == "auto" else str(mss)
            lines += [
                "  chain gateway_mss {", "    type filter hook forward priority -150; policy accept;",
                f'    iifname "{access}" oifname "{vpn}" ip saddr @gateway_sources ip daddr @corp_targets '
                f'tcp flags & (syn | rst) == syn tcp option maxseg size set {expression}',
                f'    iifname "{vpn}" oifname "{access}" ip saddr @corp_targets ip daddr @gateway_sources '
                f'tcp flags & (syn | rst) == syn tcp option maxseg size set {expression}', "  }",
            ]
    lines.append("}")
    ready = proxy_ready or gateway_ready
    return dict(
        base, status="READY" if ready else "CLOSED", effective_ready=ready,
        proxy_ready=proxy_ready, gateway_ready=gateway_ready,
        reason="FORCED_CLOSED" if closed else context["reason"], nft="\n".join(lines) + "\n",
    )


class NftRunner:
    def run(self, argv: list[str], input_text: str | None = None):
        try:
            return subprocess.run(
                argv, input=input_text, capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError("nft command unavailable or timed out") from exc


class PolicyManager:
    """Inject a fake runner for unit tests; no implicit privilege/network repair."""
    def __init__(self, context: dict[str, Any], runner=None):
        self.context = context
        self.runner = runner if runner is not None else NftRunner()

    def _json(self, argv):
        result = self.runner.run(argv)
        if result.returncode:
            raise PolicyError("cannot inspect nft table ownership")
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise PolicyError("nft inspection did not return JSON") from exc
        if not isinstance(value, dict) or not isinstance(value.get("nftables"), list):
            raise PolicyError("invalid nft ownership response")
        return value["nftables"]

    def owner_state(self):
        tables = self._json(["nft", "-j", "list", "tables"])
        matches = [entry["table"] for entry in tables if isinstance(entry, dict) and isinstance(entry.get("table"), dict)
                   and entry["table"].get("family") == FAMILY and entry["table"].get("name") == TABLE]
        if not matches:
            return None
        if len(matches) != 1:
            raise PolicyError("ambiguous nft ownership")
        entries = self._json(["nft", "-a", "-j", "list", "table", FAMILY, TABLE])
        metadata = [entry["table"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("table"), dict)
                    and entry["table"].get("family") == FAMILY and entry["table"].get("name") == TABLE]
        if len(metadata) != 1:
            raise PolicyError("missing nft table owner metadata")
        table = metadata[0]
        if table.get("comment") != owner_comment(self.context):
            raise PolicyError("nft table belongs to another/unknown owner")
        handle = table.get("handle")
        if type(handle) is not int or handle < 0:
            raise PolicyError("nft table handle is missing or invalid")
        return handle, table["comment"]

    def execute(self, operation: str = "apply", dry_run: bool = False) -> dict[str, Any]:
        if operation not in ("apply", "close", "cleanup"):
            raise PolicyError("unsupported policy operation")
        if self.context["network_mode"] == "host":
            raise PolicyError("all egress mutations are forbidden in host mode")
        if dry_run:
            result = render_policy(self.context, closed=operation == "close")
            if operation == "cleanup":
                result.update(status="PLANNED_CLEANUP", effective_ready=False, nft="")
            result.update(operation=operation, dry_run=True, requires_owner_check=True)
            return result
        initial = self.owner_state()
        if operation == "cleanup":
            text = f"delete table {FAMILY} {TABLE}\n" if initial is not None else ""
            result = {
                "schema_version": 1, "project": self.context["project"], "owner": owner_comment(self.context),
                "table": TABLE, "family": FAMILY, "status": "REMOVED" if initial is not None else "ABSENT",
                "effective_ready": False, "nft": text,
            }
        else:
            result = render_policy(self.context, exists=initial is not None, closed=operation == "close")
            text = result["nft"]
        if text:
            checked = self.runner.run(["nft", "-c", "-f", "-"], input_text=text)
            if checked.returncode:
                raise PolicyError("nft validation rejected the entire transaction; nothing applied")
            # Detect another owner/generation appearing while validation ran.
            if self.owner_state() != initial:
                raise PolicyError("nft owner/generation changed during validation; nothing applied")
            applied = self.runner.run(["nft", "-f", "-"], input_text=text)
            if applied.returncode:
                raise PolicyError("nft atomic transaction failed; no permissive fallback")
        result.update(operation=operation, dry_run=False, ownership_checked=True, kernel_syntax_checked=bool(text))
        return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("render", "apply", "close", "cleanup"))
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        context = load_context(args.context)
        result = render_policy(context) if args.command == "render" else PolicyManager(context).execute(args.command, args.dry_run)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ProxyError, PolicyError, OSError) as exc:
        print(f"egress policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
