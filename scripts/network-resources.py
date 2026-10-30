#!/usr/bin/env python3
"""Own only this project's Docker network and explicitly approved UFW rule.

No shell evaluation, global policy changes, automatic host-network fallback, or
snapshot restore. The JSON ledger contains resource identity, never credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LABEL = "io.feilian.owner"
PROJECT_LABEL = "io.feilian.project"
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class ResourceError(Exception):
    pass


class Runner:
    def call(self, args: list[str], *, check: bool = True):
        command = list(args)
        if command[0] == "ufw" and not shutil.which("ufw") and os.access("/usr/sbin/ufw", os.X_OK):
            command[0] = "/usr/sbin/ufw"
        try:
            result = subprocess.run(command, text=True, capture_output=True,
                                    env={**os.environ, "LC_ALL": "C"}, timeout=40)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ResourceError(f"cannot run {args[0]}: {exc}") from exc
        if check and result.returncode:
            raise ResourceError(f"{shlex.join(args)}: {result.stderr.strip() or 'failed'}")
        return result


def atomic_json(path: Path, data: dict) -> None:
    """Refuse symlink indirection; replace only a checked file in its own dir."""
    expected = path.absolute()
    if path.resolve() != expected or path.parent.resolve() != path.parent.absolute():
        raise ResourceError("state path must not traverse symlinks")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".network-", suffix=".tmp", delete=False) as out:
            temporary = Path(out.name)
            os.chmod(temporary, 0o600)
            json.dump(data, out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if temporary.resolve().parent != expected.parent or path.resolve() != expected:
            raise ResourceError("state target changed before replacement")
        temporary.replace(expected)
        temporary = None
    finally:
        if temporary is not None and temporary.resolve().parent == expected.parent:
            temporary.unlink(missing_ok=True)


def parse_ufw_rule(line: str) -> dict | None:
    """Canonicalize the small, explicit UFW route-allow syntax we may reuse."""
    try:
        words = shlex.split(line)
    except ValueError:
        return None
    if words[:1] == ["ufw"]:
        words = words[1:]
    if words[:2] != ["route", "allow"]:
        return None
    fields = {"in": None, "out": None, "from": "any", "to": "any", "comment": ""}
    i = 2
    while i < len(words):
        token = words[i]
        if token in ("in", "out") and words[i + 1:i + 2] == ["on"] and i + 2 < len(words):
            fields[token] = words[i + 2]
            i += 3
        elif token in ("from", "to", "comment") and i + 1 < len(words):
            fields[token] = words[i + 1]
            i += 2
        elif token == "proto" and words[i + 1:i + 2] == ["any"]:
            i += 2
        elif token in ("log", "log-all"):
            i += 1  # Preserve an existing equivalent logging rule; never replace it.
        else:
            return None
    try:
        if fields["from"] != "any":
            fields["from"] = str(ipaddress.ip_network(fields["from"], strict=False))
        if fields["to"] != "any":
            fields["to"] = str(ipaddress.ip_network(fields["to"], strict=False))
    except ValueError:
        return None
    return fields


def has_stateful_forward(raw: str) -> bool:
    state = r"(?:RELATED,ESTABLISHED|ESTABLISHED,RELATED)"
    if re.search(r"ufw-before-forward[^\n]*--ctstate " + state + r"[^\n]*-j ACCEPT", raw):
        return True
    # ufw show raw can use iptables -L rather than iptables-save formatting.
    in_chain = False
    for line in raw.splitlines():
        if line.startswith("Chain "):
            in_chain = line.startswith("Chain ufw-before-forward ")
        elif in_chain and re.search(r"\bACCEPT\b.*\bctstate " + state + r"\b", line):
            return True
    return False


class Resources:
    def __init__(self, project: str, runner=None, root: Path = ROOT):
        if not PROJECT_RE.fullmatch(project):
            raise ResourceError("invalid project name")
        self.project = project
        self.root = root.resolve()
        self.owner = hashlib.sha256(f"{self.root}:{project}".encode()).hexdigest()[:12]
        self.bridge = f"fl-{self.owner}"
        self.runner = runner or Runner()
        self.path = self.root / ".state" / project / "network.json"
        if self.path.resolve() != self.path.absolute():
            raise ResourceError("state path must not traverse symlinks")
        self.ledger = {"schema_version": 1, "owner": self.owner, "project": project,
                       "networks": [], "ufw_rules": []}
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ResourceError("unreadable network ledger; refusing mutation") from exc
            if (loaded.get("schema_version") != 1 or loaded.get("owner") != self.owner
                    or loaded.get("project") != project
                    or not isinstance(loaded.get("networks"), list)
                    or not isinstance(loaded.get("ufw_rules"), list)):
                raise ResourceError("network ledger identity mismatch")
            self.ledger = loaded

    def save(self):
        atomic_json(self.path, self.ledger)

    def call_json(self, args):
        result = self.runner.call(args)
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise ResourceError(f"invalid JSON from {args[0]}") from exc

    def inspect(self, name: str):
        result = self.runner.call(["docker", "network", "inspect", name], check=False)
        if result.returncode:
            if "not found" in result.stderr.lower() or "no such network" in result.stderr.lower():
                return None
            raise ResourceError(result.stderr.strip() or "Docker network inspection failed")
        try:
            records = json.loads(result.stdout)
            if len(records) != 1:
                raise ValueError("unexpected network count")
            return records[0]
        except (ValueError, TypeError, KeyError) as exc:
            raise ResourceError("invalid Docker network inspection") from exc

    def assert_owner(self, network, name, driver):
        labels = network.get("Labels") or {}
        if (network.get("Name") != name or network.get("Driver") != driver
                or labels.get(LABEL) != self.owner
                or labels.get(PROJECT_LABEL) != self.project):
            raise ResourceError(f"network {name} is not owned by this project/configuration")

    def ensure_bridge(self, dry_run=False):
        name = f"{self.project}-net"
        current = self.inspect(name)
        if current:
            self.assert_owner(current, name, "bridge")
            if (current.get("Options") or {}).get("com.docker.network.bridge.name") != self.bridge:
                raise ResourceError("existing bridge interface differs; refusing replacement")
            return {"action": "reuse", "network": name, "id": current["Id"], "bridge": self.bridge}
        command = ["docker", "network", "create", "--driver", "bridge", "--label",
                   f"{LABEL}={self.owner}", "--label", f"{PROJECT_LABEL}={self.project}",
                   "--opt", f"com.docker.network.bridge.name={self.bridge}", name]
        if dry_run:
            return {"action": "create", "network": name, "command": command}
        self.runner.call(command)
        created = self.inspect(name)
        if created is None:
            raise ResourceError("created network could not be verified")
        self.assert_owner(created, name, "bridge")
        self.ledger["networks"].append({"name": name, "id": created["Id"], "driver": "bridge"})
        self.save()
        return {"action": "created", "network": name, "id": created["Id"], "bridge": self.bridge}

    def ensure_access(self, subnet: str, dry_run=False):
        """Create the dedicated access network the SNAT gateway serves.

        Keeping it separate from the project bridge is what makes the gateway
        scope auditable: only containers attached here can reach corporate
        networks through this project.
        """
        try:
            network = ipaddress.ip_network(subnet or "", strict=True)
        except ValueError as exc:
            raise ResourceError("ACCESS_SUBNET must be an explicit IPv4 CIDR") from exc
        if network.version != 4 or network.prefixlen == 0:
            raise ResourceError("ACCESS_SUBNET must be a non-default IPv4 CIDR")
        name = f"{self.project}-access"
        current = self.inspect(name)
        if current:
            self.assert_owner(current, name, "bridge")
            configs = current.get("IPAM", {}).get("Config", [])
            if len(configs) != 1 or configs[0].get("Subnet") != str(network):
                raise ResourceError("existing access network uses a different subnet")
            return {"action": "reuse", "network": name, "id": current["Id"],
                    "subnet": str(network)}
        command = ["docker", "network", "create", "--driver", "bridge", "--label",
                   f"{LABEL}={self.owner}", "--label", f"{PROJECT_LABEL}={self.project}",
                   "--label", "io.feilian.role=access", "--subnet", str(network), name]
        if dry_run:
            return {"action": "create", "network": name, "command": command,
                    "subnet": str(network)}
        self.runner.call(command)
        created = self.inspect(name)
        if created is None:
            raise ResourceError("created access network could not be verified")
        self.assert_owner(created, name, "bridge")
        self.ledger["networks"].append({"name": name, "id": created["Id"],
                                        "driver": "bridge", "role": "access"})
        self.save()
        return {"action": "created", "network": name, "id": created["Id"],
                "subnet": str(network)}

    def bridge_details(self):
        name = f"{self.project}-net"
        network = self.inspect(name)
        if network is None:
            return None
        self.assert_owner(network, name, "bridge")
        if (network.get("Options") or {}).get("com.docker.network.bridge.name") != self.bridge:
            raise ResourceError("bridge interface ownership mismatch")
        subnets = []
        for item in network.get("IPAM", {}).get("Config", []):
            try:
                value = ipaddress.ip_network(item.get("Subnet", ""), strict=True)
            except ValueError as exc:
                raise ResourceError("invalid Docker bridge subnet") from exc
            if value.version == 4:
                subnets.append(str(value))
        if len(subnets) != 1:
            raise ResourceError("expected exactly one project IPv4 bridge subnet")
        return {"name": name, "id": network["Id"], "bridge": self.bridge, "subnet": subnets[0]}

    def uplink(self, explicit=""):
        if explicit:
            if not IFACE_RE.fullmatch(explicit):
                raise ResourceError("invalid uplink interface")
            self.call_json(["ip", "-j", "link", "show", "dev", explicit])
            return explicit
        routes = self.call_json(["ip", "-j", "-4", "route", "show", "default"])
        for route in sorted(routes, key=lambda r: r.get("metric", 0)):
            iface = route.get("dev", "")
            if IFACE_RE.fullmatch(iface) and iface != self.bridge:
                return iface
        raise ResourceError("no IPv4 default uplink; supply --up-if explicitly")

    @staticmethod
    def privileged(args):
        return args if os.geteuid() == 0 else ["sudo", "-n", *args]

    def ufw_state(self):
        if not shutil.which("ufw") and not os.access("/usr/sbin/ufw", os.X_OK):
            return "unavailable", []
        status = self.runner.call(self.privileged(["ufw", "status"]), check=False)
        if status.returncode:
            return "unknown", []
        state = "inactive" if "Status: inactive" in status.stdout else "active"
        if state == "active" and "Status: active" not in status.stdout:
            return "unknown", []
        # Inactive UFW still has persistent rules; cleanup must not forget them.
        added = self.runner.call(self.privileged(["ufw", "show", "added"]), check=False)
        if added.returncode:
            return "unknown", []
        return state, [rule for line in added.stdout.splitlines()
                       if (rule := parse_ufw_rule(line)) is not None]

    def rule_plan(self, up_if=""):
        details = self.bridge_details()
        uplink = self.uplink(up_if)
        if uplink == self.bridge:
            raise ResourceError("project bridge cannot be its own uplink")
        state, rules = self.ufw_state()
        result = {"project": self.project, "owner": self.owner, "network": details,
                  "uplink": uplink, "ufw": state, "commands": [],
                  "policy": "outbound project subnet only; existing UFW conntrack handles replies"}
        if details is None:
            result["reason"] = "project bridge does not exist; use ensure-bridge first"
            return result
        desired = {"in": details["bridge"], "out": uplink, "from": details["subnet"],
                   "to": "any", "comment": f"feilian:{self.project}:{self.owner}"}
        equivalent = [r for r in rules if all(r[k] == desired[k] for k in ("in", "out", "from", "to"))]
        result["equivalent_rule_exists"] = bool(equivalent)
        if state == "active" and not equivalent:
            result["commands"] = [["ufw", "route", "allow", "in", "on", details["bridge"],
                                   "out", "on", uplink, "from", details["subnet"], "to", "any",
                                   "comment", desired["comment"]]]
        return result

    def apply(self, up_if="", dry_run=False):
        plan = self.rule_plan(up_if)
        if dry_run:
            return plan
        if plan["network"] is None:
            raise ResourceError(plan["reason"])
        if plan["ufw"] == "unknown":
            raise ResourceError("UFW state is unknown; obtain explicit read/apply permission")
        for command in plan["commands"]:
            raw = self.runner.call(self.privileged(["ufw", "show", "raw"]))
            # Never compensate for missing stateful return handling with a broad reverse allow.
            if not has_stateful_forward(raw.stdout):
                raise ResourceError("UFW stateful forwarding replies not verified; refusing broad reverse rule")
            entry = {"command": command, "network_id": plan["network"]["id"], "status": "pending"}
            self.ledger["ufw_rules"].append(entry)
            self.save()  # Record intent before changing the host; reconcile after crashes.
            self.runner.call(self.privileged(command))
            entry["status"] = "applied"
            self.save()
        plan["applied"] = len(plan["commands"])
        return plan

    def doctor(self, up_if=""):
        result = self.rule_plan(up_if)
        links = self.call_json(["ip", "-j", "link", "show"])
        result["transparent_proxy_interfaces"] = [item.get("ifname") for item in links
            if re.search(r"mihomo|clash|meta", item.get("ifname", ""), re.I)]
        result["warning"] = ("Mihomo/transparent-proxy policy may still block bridge traffic; "
                             "no configuration or default route will be changed automatically.")
        return result

    def macvlan_create(self, parent, subnet, gateway, address, dry_run=False):
        if not IFACE_RE.fullmatch(parent or ""):
            raise ResourceError("explicit valid MACVLAN_PARENT required")
        if (Path("/sys/class/net") / parent / "phy80211").exists():
            raise ResourceError("wireless STA macvlan is not supported")
        try:
            net = ipaddress.ip_network(subnet, strict=True)
            gw = ipaddress.ip_address(gateway)
            addr = ipaddress.ip_address(address)
            if (net.version != 4 or gw not in net or addr not in net or gw == addr
                    or gw in (net.network_address, net.broadcast_address)
                    or addr in (net.network_address, net.broadcast_address)):
                raise ValueError("invalid usable addresses")
        except ValueError as exc:
            raise ResourceError("macvlan requires explicit IPv4 subnet, gateway and free address") from exc
        self.call_json(["ip", "-j", "link", "show", "dev", parent])
        name = f"{self.project}-macvlan"
        current = self.inspect(name)
        if current:
            self.assert_owner(current, name, "macvlan")
            configs = current.get("IPAM", {}).get("Config", [])
            if ((current.get("Options") or {}).get("parent") != parent
                    or len(configs) != 1 or configs[0].get("Subnet") != str(net)
                    or configs[0].get("Gateway") != str(gw)):
                raise ResourceError("existing macvlan differs; refusing replacement")
            return {"action": "reuse", "network": name, "id": current["Id"]}
        command = ["docker", "network", "create", "--driver", "macvlan", "--label",
                   f"{LABEL}={self.owner}", "--label", f"{PROJECT_LABEL}={self.project}",
                   "--subnet", str(net), "--gateway", str(gw), "--opt", f"parent={parent}", name]
        if dry_run:
            return {"action": "create", "network": name, "command": command}
        self.runner.call(command)
        created = self.inspect(name)
        if created is None:
            raise ResourceError("created macvlan could not be verified")
        self.assert_owner(created, name, "macvlan")
        self.ledger["networks"].append({"name": name, "id": created["Id"], "driver": "macvlan"})
        self.save()
        return {"action": "created", "network": name, "id": created["Id"]}

    def cleanup(self, include_macvlan=False, dry_run=False, macvlan_only=False):
        commands, conflicts = [], []
        state, rules = self.ufw_state() if not macvlan_only else ("not-needed", [])
        kept_rules = list(self.ledger["ufw_rules"]) if macvlan_only else []
        for entry in ([] if macvlan_only else self.ledger["ufw_rules"]):
            expected = parse_ufw_rule(shlex.join(entry.get("command", [])))
            if not expected or expected["comment"] != f"feilian:{self.project}:{self.owner}":
                raise ResourceError("invalid owned UFW ledger entry")
            if state in ("unknown", "unavailable"):
                conflicts.append("UFW state unreadable/unavailable; owned rules retained")
                kept_rules.append(entry)
                continue
            exact = expected in rules
            same_comment = any(r["comment"] == expected["comment"] for r in rules)
            if not exact:
                if same_comment:
                    conflicts.append("owned UFW comment exists with changed rule; retained")
                    kept_rules.append(entry)
                continue
            command = entry["command"]
            if command[:3] != ["ufw", "route", "allow"]:
                raise ResourceError("unexpected UFW command in ledger")
            deletion = ["ufw", "--force", "route", "delete", *command[2:]]
            commands.append(deletion)
            if not dry_run:
                self.runner.call(self.privileged(deletion))
        kept_networks = []
        for entry in self.ledger["networks"]:
            driver = entry.get("driver")
            if macvlan_only and driver == "bridge":
                kept_networks.append(entry)
                continue
            if driver == "macvlan" and not include_macvlan:
                kept_networks.append(entry)
                continue
            role = entry.get("role", "")
            name = (f"{self.project}-access" if role == "access"
                    else f"{self.project}-{'net' if driver == 'bridge' else 'macvlan'}")
            if driver not in ("bridge", "macvlan") or entry.get("name") != name:
                raise ResourceError("invalid network ledger entry")
            current = self.inspect(name)
            if current is None:
                continue
            self.assert_owner(current, name, driver)
            if current.get("Id") != entry.get("id") or current.get("Containers"):
                conflicts.append(f"{name}: ID changed or network still in use; retained")
                kept_networks.append(entry)
                continue
            # Resolve the recorded network to its live ID and verify owner before removal.
            command = ["docker", "network", "rm", current["Id"]]
            commands.append(command)
            if not dry_run:
                self.runner.call(command)
        if not dry_run:
            self.ledger["ufw_rules"] = kept_rules
            self.ledger["networks"] = kept_networks
            self.save()
        return {"project": self.project, "commands": commands, "conflicts": conflicts, "dry_run": dry_run}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "plan", "apply", "ensure-bridge", "cleanup",
                                           "macvlan-create", "macvlan-destroy"))
    parser.add_argument("--project", default=os.environ.get("PROJECT_NAME", "feilian"))
    parser.add_argument("--up-if", default=os.environ.get("UP_IF", ""))
    parser.add_argument("--parent", default=os.environ.get("MACVLAN_PARENT", ""))
    parser.add_argument("--subnet", default=os.environ.get("MACVLAN_SUBNET", ""))
    parser.add_argument("--gateway", default=os.environ.get("MACVLAN_GATEWAY", ""))
    parser.add_argument("--ip", default=os.environ.get("MACVLAN_IP", ""))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--include-macvlan", action="store_true")
    parser.add_argument("--subnet", default=os.environ.get("ACCESS_SUBNET", ""))
    args = parser.parse_args(argv)
    try:
        resources = Resources(args.project)
        if args.action == "ensure-bridge":
            result = resources.ensure_bridge(args.dry_run)
        elif args.action == "ensure-access":
            result = resources.ensure_access(args.subnet, args.dry_run)
        elif args.action == "doctor":
            result = resources.doctor(args.up_if)
        elif args.action == "plan":
            result = resources.rule_plan(args.up_if)
        elif args.action == "apply":
            result = resources.apply(args.up_if, args.dry_run)
        elif args.action == "macvlan-create":
            result = resources.macvlan_create(args.parent, args.subnet, args.gateway, args.ip, args.dry_run)
        else:
            result = resources.cleanup(args.include_macvlan or args.action == "macvlan-destroy", args.dry_run,
                                       macvlan_only=args.action == "macvlan-destroy")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result.get("conflicts") else 0
    except ResourceError as exc:
        print(f"[feilian network] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
