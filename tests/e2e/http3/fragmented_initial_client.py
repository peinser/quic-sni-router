import argparse
import select
import socket
import time

from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def make_initials(sni: str, router_host: str, router_port: int) -> list[bytes]:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.server_name = sni
    configuration.quantum_readiness_test = True
    configuration.max_datagram_size = 1250
    quic = QuicConnection(configuration=configuration)
    quic.connect((router_host, router_port), now=time.time())
    datagrams = [data for data, _ in quic.datagrams_to_send(now=time.time())]
    if len(datagrams) < 2:
        raise RuntimeError(f"expected fragmented Initial flight, got {len(datagrams)} datagram(s)")
    return datagrams


def expect_no_response(sock: socket.socket, timeout: float = 0.5) -> None:
    ready, _, _ = select.select([sock], [], [], timeout)
    if ready:
      data, _ = sock.recvfrom(2048)
      raise RuntimeError(f"unexpected response before SNI fragment arrived: {data!r}")
    print("out-of-order Initial fragment buffered", flush=True)


def expect_markers(sock: socket.socket, count: int, timeout: float = 3.0) -> None:
    seen = []
    deadline = time.monotonic() + timeout
    while len(seen) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"timed out waiting for {count} marker responses, saw {seen!r}")
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            continue
        data, _ = sock.recvfrom(2048)
        seen.append(data)
    expected = [f"marker:{i}".encode() for i in range(1, count + 1)]
    if seen != expected:
        raise RuntimeError(f"expected marker sequence {expected!r}, got {seen!r}")
    print(f"fragmented Initial flush ok: {seen!r}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument("--sni", default="fragmented.flightdeck.test")
    args = parser.parse_args()

    datagrams = make_initials(args.sni, args.router_host, args.router_port)
    router = (args.router_host, args.router_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    # Send the non-zero-offset CRYPTO fragment first. The router must buffer it
    # because it cannot see SNI yet, then flush it when the offset-0 fragment
    # arrives and SNI becomes parseable.
    sock.sendto(datagrams[1], router)
    expect_no_response(sock)
    sock.sendto(datagrams[0], router)
    expect_markers(sock, 2)


if __name__ == "__main__":
    main()
