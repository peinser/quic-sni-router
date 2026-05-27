import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    count = 0
    while True:
        data, addr = sock.recvfrom(2048)
        count += 1
        marker = f"marker:{count}".encode()
        print(f"received {len(data)} bytes from {addr}, sending {marker!r}", flush=True)
        sock.sendto(marker, addr)


if __name__ == "__main__":
    main()
