#!/usr/bin/env python3
"""Owned test DNS/HTTP/CA-HTTPS recorder, never an official client or VPN."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import signal
import socketserver
import ssl
import struct
import subprocess
import threading
import time

STATE = Path("/labstate")
LOCK = threading.Lock()


def event(role, kind, **fields):
    value = {"at": time.time(), "kind": kind, **fields}
    with LOCK:
        with (STATE / (role + ".jsonl")).open("a") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")


def dns_reply(packet, answer):
    if len(packet) < 12 or struct.unpack("!H", packet[4:6])[0] != 1:
        raise ValueError("bad_fixture_dns_question")
    offset, labels = 12, []
    for _ in range(64):
        if offset >= len(packet):
            raise ValueError("bad_fixture_dns_question")
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError("bad_fixture_dns_question")
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    else:
        raise ValueError("bad_fixture_dns_question")
    if offset + 4 != len(packet):
        raise ValueError("bad_fixture_dns_question")
    name = ".".join(labels)
    kind, klass = struct.unpack("!HH", packet[offset:])
    address = answer(name) if kind == 1 and klass == 1 else None
    header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(address)), 0, 0)
    response = header + packet[12:]
    if address:
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + ipaddress.IPv4Address(address).packed
    return name, response


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(args):
    if args.role == "idle":
        while True:
            time.sleep(3600)
    if not Path("/.dockerenv").is_file() or os.environ.get("FEILIAN_TEST_OWNER") != args.owner:
        raise ValueError("fixture_requires_owned_docker_container")
    STATE.mkdir(mode=0o700, exist_ok=True)
    if args.role == "corp":
        for address in ("10.91.0.53/32", "10.91.0.80/32"):
            subprocess.run(["ip", "address", "add", address, "dev", "lo"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dns_ip = "10.91.0.53" if args.role == "corp" else "0.0.0.0"

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            def answer(name):
                if args.role == "corp":
                    return "10.91.0.80" if name == "corp.test" or name.endswith(".corp.test") else None
                return args.answer
            try:
                name, response = dns_reply(self.request[0], answer)
            except (ValueError, UnicodeError):
                return
            event(args.role, "dns", name=name, source=self.client_address[0])
            self.request[1].sendto(response, self.client_address)

    class HTTP(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            event(args.role, "http", source=self.client_address[0], path=self.path.split("?", 1)[0])
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://login.public.test/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = ("CORP_TEST_ONLY" if args.role == "corp" else "PUBLIC_EGRESS_RECORDER").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    dns = UDPServer((dns_ip, 53), DNSHandler)
    plain = ThreadingHTTPServer(("0.0.0.0", 80), HTTP)
    secure = ThreadingHTTPServer(("0.0.0.0", 443), HTTP)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(STATE / "server.crt"), str(STATE / "server.key"))
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    for server in (dns, plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    stopped.wait()
    for server in (dns, plain, secure):
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("corp", "bootstrap", "idle"))
    parser.add_argument("--owner")
    parser.add_argument("--answer", default="192.0.2.1")
    serve(parser.parse_args())
