"""NAT-rebind regression client.

Establishes a QUIC connection through the router, keeps it alive with PING
frames until the connection is older than the router's sessions.idleTimeout,
then simulates a NAT rebinding by switching to a fresh UDP socket (new source
port) and asserts the connection still works from the new tuple.

The router can only route the rebound short-header packets via the server-CID
aliases it learned during the handshake. Those aliases see no traffic after
the handshake, so unless the router keeps them alive while the flow itself is
active, they expire after idleTimeout and the rebound packets are dropped.
That is exactly the regression this client exists to catch.
"""

import argparse
import socket
import ssl
import time

from aioquic.h3.connection import H3_ALPN
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


class RebindDriver:
    def __init__(self, quic: QuicConnection, router: tuple[str, int]) -> None:
        self.quic = quic
        self.router = router
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))

    def rebind(self) -> None:
        old_port = self.sock.getsockname()[1]
        self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        new_port = self.sock.getsockname()[1]
        print(f"rebind: source port {old_port} -> {new_port}", flush=True)

    def pump(self) -> None:
        for data, _addr in self.quic.datagrams_to_send(now=time.time()):
            self.sock.sendto(data, self.router)

    def drive(self, deadline: float, until) -> events.QuicEvent:
        """Send/receive/timers until `until(event)` is true or the deadline."""
        while time.monotonic() < deadline:
            self.pump()
            self.sock.settimeout(0.05)
            try:
                data, _addr = self.sock.recvfrom(65535)
                self.quic.receive_datagram(data, self.router, now=time.time())
            except socket.timeout:
                pass
            timer = self.quic.get_timer()
            if timer is not None and time.time() >= timer:
                self.quic.handle_timer(now=time.time())
            event = self.quic.next_event()
            while event is not None:
                if isinstance(event, events.ConnectionTerminated):
                    raise RuntimeError(f"connection terminated: {event.reason_phrase!r}")
                if until(event):
                    self.pump()
                    return event
                event = self.quic.next_event()
        raise RuntimeError("timed out waiting for QUIC event")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument("--sni", default="rebind.flightdeck.test")
    parser.add_argument("--router-idle-timeout", type=float, default=3.0)
    args = parser.parse_args()

    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.server_name = args.sni
    configuration.verify_mode = ssl.CERT_NONE
    quic = QuicConnection(configuration=configuration)
    quic.connect((args.router_host, args.router_port), now=time.time())

    driver = RebindDriver(quic, (args.router_host, args.router_port))
    driver.drive(
        time.monotonic() + 5.0,
        lambda event: isinstance(event, events.HandshakeCompleted),
    )
    print("handshake completed", flush=True)

    # Age the connection well past the router's idleTimeout. The PINGs keep
    # the router's flow (and the client/server idle timers) alive, but nothing
    # after the handshake refreshes the router's learned CID aliases.
    age_seconds = args.router_idle_timeout * 2.5 + 1.0
    age_deadline = time.monotonic() + age_seconds
    uid = 0
    while time.monotonic() < age_deadline:
        uid += 1
        quic.send_ping(uid)
        driver.drive(
            time.monotonic() + 5.0,
            lambda event: isinstance(event, events.PingAcknowledged),
        )
        time.sleep(0.5)
    print(f"aged connection {age_seconds:.1f}s with {uid} acked pings", flush=True)

    # Simulated NAT rebinding: same connection, brand-new source port.
    driver.rebind()
    uid += 1
    quic.send_ping(uid)
    driver.drive(
        time.monotonic() + 5.0,
        lambda event: isinstance(event, events.PingAcknowledged),
    )
    print("PASS: ping acknowledged after rebind on aged connection", flush=True)


if __name__ == "__main__":
    main()
