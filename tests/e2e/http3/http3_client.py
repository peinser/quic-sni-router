import argparse
import asyncio
import ssl

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._done: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()
        self._body = bytearray()

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                status = dict(http_event.headers).get(b":status")
                if status != b"200" and not self._done.done():
                    self._done.set_exception(RuntimeError(f"unexpected status {status!r}"))
            elif isinstance(http_event, DataReceived):
                self._body.extend(http_event.data)
                if http_event.stream_ended and not self._done.done():
                    self._done.set_result(bytes(self._body))

    async def get(self, authority: str, path: str) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"qsr-e2e"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(self._done, timeout=10)


# Single-version map: human-friendly name -> aioquic version constant.
# Force the configuration to send Initials in this exact version (no client-side
# fallback) so the test fails loudly if the router stops accepting either v1 or
# v2 Initials.
VERSIONS = {
    "v1": QuicProtocolVersion.VERSION_1,
    "v2": QuicProtocolVersion.VERSION_2,
}


async def fetch(router_host: str, router_port: int, sni: str, expected: str, version_name: str) -> None:
    version = VERSIONS[version_name]
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = sni
    # original_version controls the version the client sends in its first
    # Initial. Pinning supported_versions to the same single value disables the
    # client's version-negotiation fallback path — without this, an aioquic
    # client that sends a v2 Initial and gets no response would silently
    # downgrade to v1 and the test would falsely pass.
    configuration.original_version = version
    configuration.supported_versions = [version]

    last_error: Exception | None = None
    for _ in range(20):
        try:
            host = router_host if router_host != "auto" else sni
            async with asyncio.timeout(5):
                async with connect(host, router_port, configuration=configuration, create_protocol=ClientProtocol) as protocol:
                    body = await protocol.get(sni, "/")
            break
        except Exception as exc:  # noqa: BLE001 - e2e retry should report final failure only.
            last_error = exc
            await asyncio.sleep(0.5)
    else:
        raise SystemExit(f"{sni} [{version_name}]: connection failed: {last_error!r}")
    decoded = body.decode()
    if decoded != expected:
        raise SystemExit(f"{sni} [{version_name}]: expected {expected!r}, got {decoded!r}")
    print(f"{sni} [{version_name}]: {decoded.strip()}")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", default="auto")
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument(
        "--versions",
        default="v1,v2",
        help="Comma-separated QUIC versions to exercise; subset of {v1, v2}.",
    )
    args = parser.parse_args()
    requested = [v.strip() for v in args.versions.split(",") if v.strip()]
    for v in requested:
        if v not in VERSIONS:
            raise SystemExit(f"unknown version {v!r}; want subset of {sorted(VERSIONS)}")

    targets = [
        ("rvr-a.flightdeck.test", "hello from rvr-a\n"),
        ("rvr-b.flightdeck.test", "hello from rvr-b\n"),
    ]
    # Cross-product (version × backend). Each version negotiates a fresh QUIC
    # connection, so the router exercises Initial-parse + key-derive + SNI
    # extraction once per (version, backend) pair.
    for version_name in requested:
        for sni, expected in targets:
            await fetch(args.router_host, args.router_port, sni, expected, version_name)


if __name__ == "__main__":
    asyncio.run(main())
