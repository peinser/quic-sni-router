import argparse
import select
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


def recv_exact(sock: socket.socket, expected: bytes, label: str, timeout: float = 3.0) -> None:
    sock.settimeout(timeout)
    data, _ = sock.recvfrom(2048)
    if data != expected:
        raise RuntimeError(f"{label}: expected {expected!r}, got {data!r}")
    print(f"{label}: received {data!r}", flush=True)


def recv_from_either(sock_a: socket.socket, sock_b: socket.socket, expected: bytes, timeout: float = 3.0) -> str:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"timed out waiting for {expected!r} on either client")
        ready, _, _ = select.select([sock_a, sock_b], [], [], remaining)
        for sock in ready:
            data, _ = sock.recvfrom(2048)
            who = "A" if sock is sock_a else "B"
            if data != expected:
                raise RuntimeError(f"client {who}: expected {expected!r}, got {data!r}")
            print(f"client {who}: received {data!r}", flush=True)
            return who


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument("--sni", default="reverse.flightdeck.test")
    args = parser.parse_args()

    router = (args.router_host, args.router_port)
    initial_a = make_initial(args.sni, args.router_host, args.router_port)
    initial_b = make_initial(args.sni, args.router_host, args.router_port)

    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_a.bind(("0.0.0.0", 0))
    sock_b.bind(("0.0.0.0", 0))

    sock_a.sendto(initial_a, router)
    recv_exact(sock_a, b"marker:1", "client A initial")

    sock_b.sendto(initial_b, router)
    recv_exact(sock_b, b"marker:2", "client B initial")

    # This simulates client A sending a 1-RTT packet on an old connection after
    # the backend has timed it out. The backend's response/reset is not
    # CID-routeable by the router, so it must follow the refreshed reverse tuple.
    sock_a.sendto(b"\x40old-connection-after-backend-idle", router)
    recipient = recv_from_either(sock_a, sock_b, b"marker:3")
    if recipient != "A":
        raise SystemExit("stale backend reverse tuple: post-idle response went to client B")

    print("reverse tuple refresh ok", flush=True)


if __name__ == "__main__":
    main()
