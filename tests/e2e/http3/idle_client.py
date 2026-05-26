import argparse
import asyncio
import ssl

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses: dict[int, asyncio.Future[bytes]] = {}
        self._bodies: dict[int, bytearray] = {}

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                status = dict(http_event.headers).get(b":status")
                future = self._responses.get(http_event.stream_id)
                if status != b"200" and future is not None and not future.done():
                    future.set_exception(RuntimeError(f"unexpected status {status!r}"))
            elif isinstance(http_event, DataReceived):
                body = self._bodies.setdefault(http_event.stream_id, bytearray())
                body.extend(http_event.data)
                future = self._responses.get(http_event.stream_id)
                if http_event.stream_ended and future is not None and not future.done():
                    future.set_result(bytes(body))

    async def get(self, authority: str, path: str, timeout: float = 5.0) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()
        self._responses[stream_id] = future
        self._bodies[stream_id] = bytearray()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"qsr-idle-e2e"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(future, timeout=timeout)


def make_config(sni: str, session_ticket=None) -> QuicConfiguration:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = sni
    if session_ticket is not None:
        configuration.session_ticket = session_ticket
    return configuration


async def fetch_once(host: str, port: int, sni: str, session_ticket=None, ticket_store=None) -> bytes:
    configuration = make_config(sni, session_ticket=session_ticket)
    kwargs = {}
    if ticket_store is not None:
        kwargs["session_ticket_handler"] = ticket_store.append
    async with asyncio.timeout(10):
        async with connect(host, port, configuration=configuration, create_protocol=ClientProtocol, **kwargs) as protocol:
            return await protocol.get(sni, "/")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-port", type=int, default=443)
    parser.add_argument("--sni", default="idle.flightdeck.test")
    parser.add_argument("--expected", default="hello from idle\n")
    parser.add_argument("--idle-wait", type=float, default=3.0)
    args = parser.parse_args()

    tickets = []
    first = await fetch_once(args.router_host, args.router_port, args.sni, ticket_store=tickets)
    if first.decode() != args.expected:
        raise SystemExit(f"first request: expected {args.expected!r}, got {first.decode()!r}")
    print("first request ok")

    configuration = make_config(args.sni, session_ticket=tickets[-1] if tickets else None)
    try:
        async with asyncio.timeout(args.idle_wait + 10):
            async with connect(
                args.router_host,
                args.router_port,
                configuration=configuration,
                create_protocol=ClientProtocol,
            ) as protocol:
                second = await protocol.get(args.sni, "/")
                if second.decode() != args.expected:
                    raise SystemExit(f"second request: expected {args.expected!r}, got {second.decode()!r}")
                print("second request ok")
                await asyncio.sleep(args.idle_wait)
                try:
                    await protocol.get(args.sni, "/", timeout=2.0)
                    print("post-idle same-connection request unexpectedly succeeded")
                except Exception as exc:  # noqa: BLE001 - the close mode is stack/version dependent.
                    print(f"post-idle same-connection request failed as expected: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 - failing here is diagnostic but not the pass criterion.
        print(f"connection closed during idle wait: {type(exc).__name__}")

    resumed_ticket = tickets[-1] if tickets else None
    final = await fetch_once(args.router_host, args.router_port, args.sni, session_ticket=resumed_ticket)
    if final.decode() != args.expected:
        raise SystemExit(f"fresh post-idle request: expected {args.expected!r}, got {final.decode()!r}")
    print("fresh post-idle request ok")


if __name__ == "__main__":
    asyncio.run(main())
