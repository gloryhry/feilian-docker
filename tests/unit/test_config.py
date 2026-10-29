"""Offline tests for config.py/config.sh only: no daemon, network or credentials."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/config.py"
LIBRARY = ROOT / "scripts/lib/config.sh"
spec = importlib.util.spec_from_file_location("feilian_config_test", SCRIPT)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="feilian-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "test.env"
        self.manifest = self.root / "client.lock.json"
        self.environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                            "HOME": str(self.root), "PYTHONDONTWRITEBYTECODE": "1"}

    def load(self, text="", env=None, overrides=()):
        self.file.write_text(text, encoding="utf-8")
        return config.load_config(str(self.file), environ=env or {},
                                  overrides=overrides, project_root=self.root)

    def cli(self, text="", *args, env=None):
        self.file.write_text("CLIENT_MANIFEST={}\n{}".format(self.manifest, text), encoding="utf-8")
        environment = dict(self.environment)
        environment.update(env or {})
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *args,
                               "--config", str(self.file)], env=environment,
                              text=True, capture_output=True, check=False)

    def shell(self, body, text=""):
        self.file.write_text("CLIENT_MANIFEST={}\n{}".format(self.manifest, text), encoding="utf-8")
        script = "set -u\nsource {}\n{}".format(shlex.quote(str(LIBRARY)), body)
        return subprocess.run(["bash", "-c", script, "test", str(self.file)],
                              env=self.environment, text=True, capture_output=True, check=False)

    def test_safe_defaults_and_missing_default_file(self):
        result = config.load_config(environ={}, project_root=self.root)
        self.assertEqual(result["IMAGE_REF"], "feilian-gui:3.2.16-wrapper-dev")
        self.assertEqual(result["NET_MODE"], "bridge")
        self.assertEqual(result["WEB_BIND"], "127.0.0.1")
        self.assertEqual(result["PROXY_BIND"], "127.0.0.1")
        self.assertEqual(result["WEB_AUTH"], "1")
        self.assertEqual(result["HOST_NET_APPLY"], "0")
        self.assertEqual(result["PROBE_TIMEOUT"], "8")
        self.assertEqual(result["STOP_TIMEOUT"], "20")
        self.assertEqual(result["UP_IF"], "")
        self.assertEqual(result["VPN_PROBE_CA_FILE"], "")
        self.assertEqual(result["REGISTRY_IMAGE"], "ghcr.io/gloryhry/feilian-docker")
        self.assertEqual(result["FEILIAN_CONFIG_STATUS"], "UNCONFIGURED")
        self.assertEqual(result["VPN_PROBE_URL"], "")
        self.assertEqual(result["VPN_PROBE_DNS_NAME"], "")

    def test_explicit_missing_file_is_error(self):
        with self.assertRaises(config.ConfigError):
            config.load_config(str(self.root / "missing.env"), environ={}, project_root=self.root)

    def test_precedence_and_unrelated_environment(self):
        result = self.load("NOVNC_HOST_PORT=6001\n", {"NOVNC_HOST_PORT": "6002", "PATH": "ignored"},
                           ["NOVNC_HOST_PORT=6003"])
        self.assertEqual(result["NOVNC_HOST_PORT"], "6003")
        self.assertEqual(result["NOVNC_PORT"], "6003")

    def test_literal_quotes_crlf_and_comments(self):
        result = self.load("# comment\r\nGUI_MODE='vnc'\r\n WEB_AUTH = \"1\" \r\n")
        self.assertEqual(result["GUI_MODE"], "vnc")

    def test_duplicate_unknown_and_export_directive(self):
        for text in ("WEB_AUTH=1\nWEB_AUTH=1\n", "TYPO=1\n", "export WEB_AUTH=1\n", "FEILIAN_CONFIG_STATUS=CONFIGURED\n"):
            with self.subTest(text=text), self.assertRaises(config.ConfigError):
                self.load(text)

    def test_injection_is_rejected_without_execution(self):
        marker = self.root / "must-not-exist"
        for value in ("$(touch {})".format(marker), "`id`", "${HOME}", "1;id", "1|id", "1&id", "1>file", "1\\n", "'$(id)'", '"$(id)"'):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                self.load("DEBIAN_MIRROR={}\n".format(value))
        self.assertFalse(marker.exists())

    def test_environment_and_cli_injection(self):
        for env, items in (({"GUI_MODE": "$(id)"}, []), ({"WEB_BIND": "127.0.0.1\nTAG=evil"}, []),
                           ({}, ["PROJECT_NAME=x;id"]), ({}, ["UNKNOWN=x"])):
            with self.subTest(env=env, items=items), self.assertRaises(config.ConfigError):
                self.load(env=env, overrides=items)

    def test_duplicate_set_and_alias_conflict(self):
        for items in (["WEB_AUTH=1", "WEB_AUTH=1"], ["TAG=old:v1", "IMAGE_REF=new:v2"]):
            with self.subTest(items=items), self.assertRaises(config.ConfigError):
                self.load(overrides=items)
        with self.assertRaises(config.ConfigError):
            self.load("NOVNC_PORT=6000\nNOVNC_HOST_PORT=6001\n")

    def test_aliases_with_same_value_and_precedence(self):
        result = self.load("TAG=old:v1\n", {"IMAGE_REF": "new:v2"}, ["TAG=new:v3", "IMAGE_REF=new:v3"])
        self.assertEqual(result["IMAGE_REF"], "new:v3")
        self.assertEqual(result["TAG"], "new:v3")

    def test_plaintext_password_rejected_never_echoed(self):
        secret = "test-sentinel-not-a-real-secret"
        for text, args, env in (("VNC_PASSWORD={}\n".format(secret), [], {}),
                                ("", ["--set", "VNC_PASSWORD=" + secret], {}),
                                ("", [], {"VNC_PASSWORD": secret})):
            result = self.cli(text, "render", *args, env=env)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(secret, result.stderr)
            self.assertIn("VNC_PASSWORD_FILE", result.stderr)

    def test_manifest_exact_release_schema(self):
        self.manifest.write_text(json.dumps({"schema_version": 1, "release": {"version": "4.5.6", "revision": "r1"}}))
        self.assertEqual(self.load("CLIENT_MANIFEST={}\n".format(self.manifest))["IMAGE_REF"], "feilian-gui:4.5.6-wrapper-dev")

    def test_manifest_does_not_guess_legacy_schema(self):
        for manifest in ({"version": "9.9.9"}, {"schema_version": 1, "client": {"version": "9.9.9"}},
                         {"schema_version": True, "release": {"version": "9.9.9"}},
                         {"schema_version": 1, "release": {"version": "$(id)"}}):
            self.manifest.write_text(json.dumps(manifest))
            with self.subTest(manifest=manifest), self.assertRaises(config.ConfigError):
                self.load("CLIENT_MANIFEST={}\n".format(self.manifest))

    def test_explicit_image_takes_precedence_over_manifest_default(self):
        self.assertEqual(self.load(overrides=["IMAGE_REF=local:test"])["IMAGE_REF"], "local:test")

    def test_auto_means_bridge_without_host_fallback(self):
        self.assertEqual(self.load("NET_MODE=auto\n")["NET_MODE"], "bridge")

    def test_host_requires_explicit_permission(self):
        with self.assertRaises(config.ConfigError):
            self.load("NET_MODE=host\n")

    def test_host_mode_deactivates_non_explicit_managed_defaults(self):
        result = self.load("NET_MODE=host\nALLOW_HOST_NETWORK=1\n")
        for key, expected in (("PROXY_ENABLED", "0"), ("DNS_MODE", "off"), ("GUARD_ENABLED", "0"), ("START_NETWORKMANAGER", "0")):
            self.assertEqual(result[key], expected)

    def test_host_rejects_explicit_managed_features(self):
        for setting in ("PROXY_ENABLED=1", "DNS_MODE=auto", "DNS_MODE=split", "GUARD_ENABLED=1", "START_NETWORKMANAGER=1", "GATEWAY_ENABLED=1", "MSS_MODE=auto", "MSS_MODE=1400"):
            with self.subTest(setting=setting), self.assertRaises(config.ConfigError):
                self.load("NET_MODE=host\nALLOW_HOST_NETWORK=1\n{}\n".format(setting))

    def test_host_accepts_explicit_disabled_features(self):
        result = self.load("NET_MODE=host\nALLOW_HOST_NETWORK=1\nPROXY_ENABLED=0\nDNS_MODE=off\nGUARD_ENABLED=0\nSTART_NETWORKMANAGER=0\n")
        self.assertEqual(result["NET_MODE"], "host")

    def test_web_lan_requires_all_security_controls(self):
        for settings in ("", "WEB_AUTH=0\nWEB_TLS=selfsigned\nWEB_SOURCE_CIDRS=192.0.2.0/24\n", "WEB_TLS=selfsigned\n", "WEB_SOURCE_CIDRS=192.0.2.0/24\n"):
            with self.subTest(settings=settings), self.assertRaises(config.ConfigError):
                self.load("WEB_BIND=0.0.0.0\n" + settings)
        result = self.load("WEB_BIND=0.0.0.0\nWEB_TLS=selfsigned\nWEB_SOURCE_CIDRS=192.0.2.0/24\n")
        self.assertEqual(result["WEB_BIND"], "0.0.0.0")

    def test_raw_proxy_lan_is_always_rejected(self):
        for bind in ("0.0.0.0", "192.0.2.2", "::"):
            with self.subTest(bind=bind), self.assertRaises(config.ConfigError):
                self.load("PROXY_BIND={}\nPROXY_SOURCE_CIDRS=192.0.2.0/24\n".format(bind))
        self.assertEqual(self.load("PROXY_BIND=::1\n")["PROXY_BIND"], "::1")

    def test_provided_tls_validates_paths_without_reading(self):
        with self.assertRaises(config.ConfigError):
            self.load("WEB_TLS=provided\n")
        result = self.load("WEB_TLS=provided\nWEB_TLS_CERT_FILE=/not-mounted/cert.pem\nWEB_TLS_KEY_FILE=/not-mounted/key.pem\nVNC_PASSWORD_FILE=secrets/vnc.pass\n")
        self.assertEqual(result["VNC_PASSWORD_FILE"], "secrets/vnc.pass")

    def test_probe_ca_only_absolute_path_without_reading(self):
        self.assertEqual(self.load("VPN_PROBE_CA_FILE=/not-mounted/ca.pem\n")["VPN_PROBE_CA_FILE"], "/not-mounted/ca.pem")
        with self.assertRaises(config.ConfigError):
            self.load("VPN_PROBE_CA_FILE=relative.pem\n")

    def test_macvlan_complete_security_contract(self):
        settings = "NET_MODE=macvlan\nMACVLAN_PARENT=eth0\nMACVLAN_SUBNET=192.0.2.0/24\nMACVLAN_IP=192.0.2.5\nMACVLAN_GATEWAY=192.0.2.1\nWEB_TLS=selfsigned\nWEB_SOURCE_CIDRS=198.51.100.0/24\n"
        self.assertEqual(self.load(settings)["NET_MODE"], "macvlan")
        for line in ("MACVLAN_PARENT=eth0\n", "MACVLAN_IP=192.0.2.5\n", "WEB_TLS=selfsigned\n", "WEB_SOURCE_CIDRS=198.51.100.0/24\n"):
            with self.subTest(line=line), self.assertRaises(config.ConfigError):
                self.load(settings.replace(line, ""))
        with self.assertRaises(config.ConfigError):
            self.load(settings.replace("192.0.2.5", "198.51.100.5"))

    def test_macvlan_shim_requires_mode_and_unique_host(self):
        with self.assertRaises(config.ConfigError):
            self.load("MACVLAN_SHIM=1\nMACVLAN_SHIM_IP=192.0.2.2\n")

    def test_gateway_requires_complete_nonoverlapping_addresses(self):
        settings = "GATEWAY_ENABLED=1\nGATEWAY_SOURCE_CIDRS=172.30.0.128/25\nCORP_CIDRS=10.20.0.0/16\nACCESS_SUBNET=172.30.0.0/24\nGATEWAY_IP=172.30.0.2\n"
        self.assertEqual(self.load(settings)["GATEWAY_ENABLED"], "1")
        for broken in (settings.replace("CORP_CIDRS=10.20.0.0/16\n", ""),
                       settings.replace("10.20.0.0/16", "172.30.0.0/16"),
                       settings.replace("172.30.0.2", "172.31.0.2"),
                       settings.replace("172.30.0.2", "172.30.0.0"),
                       settings.replace("172.30.0.128/25", "10.20.1.0/24"),
                       settings.replace("172.30.0.128/25", "192.0.2.0/24")):
            with self.subTest(broken=broken), self.assertRaises(config.ConfigError):
                self.load(broken)

    def test_invalid_schema_values(self):
        for setting in ("NET_MODE=bad", "NOVNC_HOST_PORT=0", "HTTP_PROXY_INTERNAL_PORT=65536", "ALLOW_HOST_NETWORK=true", "PROBE_TIMEOUT=0", "STOP_TIMEOUT=-1", "UP_IF=-bad", "VPN_IFACE=waytoolonginterfacename", "CORP_CIDRS=10.0.0.1/24", "WEB_SOURCE_CIDRS=0.0.0.0/0", "VPN_DNS=resolver.invalid", "PROXY_CONNECT_PORTS=443,443", "MSS_MODE=number", "MSS_MODE=12", "VNC_GEOMETRY=1x1x24", "X11_DISPLAY=remote:0", "VPN_PROBE_EXPECT_STATUS=999", "VPN_PROBE_URL=https://user:pass@example.invalid/", "BUILD_NETWORK=unsafe", "BUILD_PLATFORMS=windows/amd64"):
            with self.subTest(setting=setting), self.assertRaises(config.ConfigError):
                self.load(setting + "\n")

    def test_fail_closed_features_and_ipv4_resource_limits(self):
        for setting in ("PROXY_REQUIRE_VPN=0", "GUARD_ENABLED=0", "MSS_MODE=auto", "MSS_MODE=1400",
                        "ACCESS_SUBNET=2001:db8::/64", "GATEWAY_IP=2001:db8::2",
                        "MACVLAN_SUBNET=2001:db8::/64", "MACVLAN_IP=2001:db8::2",
                        "VPN_PROBE_URL=http://vpn.example.invalid/health"):
            with self.subTest(setting=setting), self.assertRaises(config.ConfigError):
                self.load(setting + "\n")
        with self.assertRaises(config.ConfigError):
            self.load("PROXY_ENABLED=0\nGATEWAY_ENABLED=1\nGUARD_ENABLED=0\n")
        with self.assertRaises(config.ConfigError):
            self.load("NET_MODE=host\nALLOW_HOST_NETWORK=1\nWEB_BIND=0.0.0.0\nWEB_TLS=selfsigned\nWEB_SOURCE_CIDRS=192.0.2.0/24\n")
        self.assertEqual(self.load("DEBIAN_MIRROR=http://mirror.example.invalid/debian\n")["DEBIAN_MIRROR"], "http://mirror.example.invalid/debian")
        self.assertEqual(self.load("VPN_PROBE_URL=https://vpn.example.invalid/health\n")["VPN_PROBE_URL"], "https://vpn.example.invalid/health")

    def test_domains_and_manual_dns_normalized(self):
        result = self.load("CORP_DOMAINS=.Corp.Example.,intranet\nVPN_DNS_SOURCE=manual\nVPN_DNS=10.20.0.53,2001:db8::53\nVPN_PROBE_DNS_NAME=Vpn.Corp.Example.\n")
        self.assertEqual(result["CORP_DOMAINS"], "corp.example,intranet")
        self.assertEqual(result["VPN_PROBE_DNS_NAME"], "vpn.corp.example")
        self.assertEqual(result["FEILIAN_CONFIG_STATUS"], "CONFIGURED")

    def test_no_enterprise_config_keeps_gui_available_unconfigured(self):
        result = self.load("DNS_MODE=split\nVPN_DNS_SOURCE=manual\n")
        self.assertEqual(result["START_GUI"], "1")
        self.assertEqual(result["FEILIAN_CONFIG_STATUS"], "UNCONFIGURED")
        self.assertEqual(result["VPN_PROBE_URL"], "")

    def test_build_multiplatform_requires_non_load_output(self):
        with self.assertRaises(config.ConfigError):
            self.load("BUILD_PLATFORMS=linux/amd64,linux/arm64\n")
        self.assertEqual(self.load("BUILD_PLATFORMS=linux/amd64,linux/arm64\nBUILD_OUTPUT=oci\n")["BUILD_OUTPUT"], "oci")

    def test_json_redacted_and_env_nonsecret_whitelist(self):
        result = self.load()
        env = config.render_env(result)
        self.assertNotIn("VNC_PASSWORD=", env)
        self.assertIn("VNC_PASSWORD_FILE=\n", env)
        self.assertEqual(set(line.split("=", 1)[0] for line in env.splitlines()), (config.INPUT_KEYS | {"FEILIAN_CONFIG_STATUS"}) - config.SECRET_KEYS)
        self.assertEqual(json.loads(config.render_json(result))["VNC_PASSWORD"], "<redacted>")

    def test_cli_validate_render_and_error_exit_codes(self):
        self.assertEqual(self.cli("", "validate").returncode, 0)
        result = self.cli("", "render", "--format", "json", "--set", "NOVNC_PORT=6090")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["NOVNC_HOST_PORT"], "6090")
        for text in ("UNKNOWN=1\n", "WEB_AUTH=1\nWEB_AUTH=1\n", "TAG=$(id)\n"):
            result = self.cli(text, "render")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_bash_adapter_exports_validated_data_and_root(self):
        result = self.shell('feilian_load_config --config "$1" --set NOVNC_PORT=6091 || exit $?; printf "%s|%s|%s|%s" "$NOVNC_HOST_PORT" "$NOVNC_PORT" "$FEILIAN_ROOT" "${VNC_PASSWORD-unset}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "6091|6091|{}|unset".format(ROOT))

    def test_bash_adapter_does_not_hide_python_failure_or_export_output(self):
        result = self.shell('PROJECT_NAME=unchanged; python3() { printf "PROJECT_NAME=tainted\\n"; return 7; }; feilian_load_config --config "$1"; rc=$?; printf "%s|%s|%s" "$rc" "$PROJECT_NAME" "${FEILIAN_ROOT-unset}"')
        self.assertEqual(result.stdout, "7|unchanged|unset")

    def test_bash_adapter_failure_leaves_environment_unchanged(self):
        result = self.shell('PROJECT_NAME=unchanged; feilian_load_config --config "$1"; rc=$?; printf "%s|%s" "$rc" "$PROJECT_NAME"', "UNKNOWN=x\n")
        self.assertEqual(result.stdout, "2|unchanged")

    def test_bash_rejects_unexpected_output_before_export(self):
        result = self.shell('PROJECT_NAME=unchanged; python3() { printf "PROJECT_NAME=tainted\\nPATH=bad\\n"; }; feilian_load_config; rc=$?; printf "%s|%s" "$rc" "$PROJECT_NAME"')
        self.assertEqual(result.stdout, "2|unchanged")

    def test_example_is_valid_without_source_or_secret_file_reads(self):
        result = config.load_config(str(ROOT / ".env.example"), environ={}, project_root=self.root)
        self.assertEqual(result["WEB_BIND"], "127.0.0.1")
        self.assertEqual(result["FEILIAN_CONFIG_STATUS"], "UNCONFIGURED")


if __name__ == "__main__":
    unittest.main()
