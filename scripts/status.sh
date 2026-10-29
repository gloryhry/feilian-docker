#!/usr/bin/env bash
# Merge runtime liveness with VPN readiness. Never prints secret material.
set -Eeuo pipefail
STATE_DIR=${STATE_DIR:-/run/feilian}
python3 - "$STATE_DIR" <<'PY'
import json, os, sys, time
from pathlib import Path

state_dir = Path(sys.argv[1])
result = {"schema_version": 1, "runtime": None, "vpn": None,
          "runtime_live": False, "vpn_ready": False}
for key, name in (("runtime", "runtime.json"), ("vpn", "status.json")):
    path = state_dir / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("schema_version") == 1:
            result[key] = data
    except (OSError, ValueError):
        pass
runtime = result["runtime"]
if runtime:
    try:
        result["runtime_live"] = time.time() - float(runtime.get("updated_at", 0)) <= 45
    except (TypeError, ValueError):
        result["runtime_live"] = False
vpn = result["vpn"]
if vpn:
    try:
        fresh = time.time() - float(vpn.get("updated_at", 0)) <= 60
    except (TypeError, ValueError):
        fresh = False
    result["vpn_ready"] = bool(fresh and vpn.get("ready") is True and vpn.get("state") == "READY")
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["runtime_live"] else 1)
PY
