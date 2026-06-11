"""UDP backend that answers every datagram with the source address it saw.

Used by the flows e2e test to assert that the router gives each client flow
its own upstream socket: two concurrent clients must be observed by the
backend as two distinct router source ports, and each reply must come back
to the client whose flow carried the request.
"""

import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    while True:
        data, addr = sock.recvfrom(4096)
        reply = f"addr:{addr[0]}:{addr[1]}".encode()
        print(f"received {len(data)} bytes from {addr}, sending {reply!r}", flush=True)
        sock.sendto(reply, addr)


if __name__ == "__main__":
    main()
