"""Verify per-flow upstream sockets: two concurrent clients to ONE backend.

Asserts the property that fixes multi-connection-per-backend routing:

  1. The backend observes a distinct router source port per client (the
     addr-echo reply payloads differ), so backend->router traffic is
     demultiplexed by socket, not by guessing connection IDs.
  2. Replies to interleaved short-header packets each arrive at the client
     that sent the request, even though the payloads carry no usable QUIC
     connection ID (the old single-socket design could only route these via
     one shared backend->client reverse tuple, i.e. to the last sender).
  3. Clients keep seeing the router's listen tuple as the reply source.
"""

import argparse
import socket
import time

from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def make_initial(sni: str, router_host: str, router_port: int) -> bytes:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.server_name = sni
    quic = QuicConnection(configuration=configuration)
    quic.connect((router_host, router_port), now=time.time())
    datagrams = quic.datagrams_to_send(now=time.time())
    if not datagrams:
        raise RuntimeError("aioquic produced no Initial datagram")
    return datagrams[0][0]


def recv_addr_echo(sock: socket.socket, router: tuple, label: str, timeout: float = 3.0) -> str:
    sock.settimeout(timeout)
    data, source = sock.recvfrom(2048)
    if not data.startswith(b"addr:"):
        raise RuntimeError(f"{label}: expected addr echo, got {data!r}")
    if source[1] != router[1]:
        raise RuntimeError(f"{label}: reply came from {source}, expected router port {router[1]}")
    print(f"{label}: backend saw {data!r}", flush=True)
    return data.decode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument("--sni", default="flows.flightdeck.test")
    args = parser.parse_args()

    router = (args.router_host, args.router_port)
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_a.bind(("0.0.0.0", 0))
    sock_b.bind(("0.0.0.0", 0))

    sock_a.sendto(make_initial(args.sni, args.router_host, args.router_port), router)
    addr_a = recv_addr_echo(sock_a, router, "client A initial")
    sock_b.sendto(make_initial(args.sni, args.router_host, args.router_port), router)
    addr_b = recv_addr_echo(sock_b, router, "client B initial")

    if addr_a == addr_b:
        raise SystemExit(f"backend saw one upstream tuple for two clients ({addr_a}); flows are not isolated")

    # Interleave short-header packets (0x40 = short header + fixed bit) from
    # both established sessions BEFORE reading any reply. The echo payloads
    # carry no QUIC CIDs, so only per-flow sockets can route both correctly.
    sock_a.sendto(b"\x40short-from-a-padded-past-min-len", router)
    sock_b.sendto(b"\x40short-from-b-padded-past-min-len", router)
    late_a = recv_addr_echo(sock_a, router, "client A short")
    late_b = recv_addr_echo(sock_b, router, "client B short")
    if late_a != addr_a or late_b != addr_b:
        raise SystemExit("flow tuple changed mid-session: A {late_a}/{addr_a}, B {late_b}/{addr_b}")

    print("per-flow upstream isolation ok", flush=True)


if __name__ == "__main__":
    main()
