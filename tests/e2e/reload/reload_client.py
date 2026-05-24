"""
Single-shot QUIC + HTTP/3 probe used by the reload e2e.

Distinct from the SNI-routing http3_client because the reload test needs
fine-grained control: probe one SNI at a time, with a tight timeout, and
either assert success-with-body or assert deterministic failure (used before
the new route exists in the reloaded config).
"""
import argparse
import asyncio
import ssl
import sys

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
                (b"user-agent", b"qsr-e2e-reload"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(self._done, timeout=3)


VERSIONS = {
    "v1": QuicProtocolVersion.VERSION_1,
    "v2": QuicProtocolVersion.VERSION_2,
}


async def attempt(host: str, port: int, sni: str, version_name: str, timeout: float) -> bytes:
    version = VERSIONS[version_name]
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = sni
    # Pin both fields: without supported_versions the client would silently
    # downgrade if its first Initial got dropped by the router (no route,
    # pre-reload). We want a clean timeout instead.
    configuration.original_version = version
    configuration.supported_versions = [version]
    async with asyncio.timeout(timeout):
        async with connect(host, port, configuration=configuration, create_protocol=ClientProtocol) as protocol:
            return await protocol.get(sni, "/")


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", required=True)
    parser.add_argument("--expected", default=None)
    parser.add_argument("--expect-fail", action="store_true",
                        help="Treat connection failure as success (route should not exist).")
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--version", default="v1", choices=sorted(VERSIONS))
    args = parser.parse_args()

    try:
        body = await attempt(args.host, args.port, args.sni, args.version, args.timeout)
    except Exception as exc:  # noqa: BLE001 - we explicitly want to see every failure mode
        if args.expect_fail:
            print(f"{args.sni} [{args.version}]: expected failure -> {type(exc).__name__}")
            return 0
        print(f"{args.sni} [{args.version}]: connection failed: {exc!r}", file=sys.stderr)
        return 1

    if args.expect_fail:
        print(f"{args.sni} [{args.version}]: unexpected success", file=sys.stderr)
        return 1
    decoded = body.decode()
    if args.expected is not None and decoded != args.expected:
        print(f"{args.sni} [{args.version}]: expected {args.expected!r}, got {decoded!r}", file=sys.stderr)
        return 1
    print(f"{args.sni} [{args.version}]: {decoded.strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
