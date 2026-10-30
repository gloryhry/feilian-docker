#!/usr/bin/env python3
"""TEST ONLY: real Linux TUN carrying IPv4 over isolated plaintext UDP.

NOT FeiLian, NOT a VPN protocol, no cryptography/authentication, no host operation.
Require a Docker container marker, matching explicit test owner and lab-prefixed
interface. The parent driver creates only private/internal Docker networks.
"""
import argparse
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess

TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000


def validate(args):
    if not Path("/.dockerenv").is_file() or os.environ.get("FEILIAN_TEST_OWNER") != args.owner:
        raise ValueError("test_fixture_requires_owned_docker_container")
    if not re.fullmatch(r"lab[a-z0-9]{1,10}", args.interface):
        raise ValueError("only_lab_interfaces_allowed")
    address = ipaddress.ip_interface(args.address)
    peer = ipaddress.ip_address(args.peer)
    transport = ipaddress.ip_address(args.udp_peer)
    if address.version != 4 or address.network.prefixlen != 30 or peer not in address.network or not transport.is_private:
        raise ValueError("invalid_isolated_test_tunnel")
    for value in args.route:
        network = ipaddress.ip_network(value, strict=True)
        if network.version != 4 or not network.is_private or network.prefixlen < 16:
            raise ValueError("only_narrow_private_fixture_routes_allowed")


def run(args):
    validate(args)
    stop = False

    def stopping(*_):
        nonlocal stop
        stop = True

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stopping)
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    try:
        fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", args.interface.encode(), IFF_TUN | IFF_NO_PI))
        for command in (["ip", "address", "add", args.address, "dev", args.interface],
                        ["ip", "link", "set", "dev", args.interface, "up"],
                        *(["ip", "route", "add", value, "via", args.peer, "dev", args.interface] for value in args.route)):
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("0.0.0.0", args.udp_port))
            sock.connect((args.udp_peer, args.udp_port))
            sock.setblocking(False)
            while not stop:
                readable, _, _ = select.select([fd, sock], [], [], 0.25)
                for source in readable:
                    try:
                        packet = os.read(fd, 65535) if source == fd else sock.recv(65535)
                        if len(packet) < 20 or packet[0] >> 4 != 4 or struct.unpack("!H", packet[2:4])[0] != len(packet):
                            continue
                        if source == fd:
                            sock.send(packet)
                        else:
                            os.write(fd, packet)
                    except (BlockingIOError, ConnectionRefusedError):
                        continue
    finally:
        os.close(fd)  # nonpersistent TUN and its routes disappear with the fd


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--interface", default="labtun0")
    parser.add_argument("--address", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--udp-peer", required=True)
    parser.add_argument("--udp-port", type=int, default=4242)
    parser.add_argument("--route", action="append", default=[])
    run(parser.parse_args())
