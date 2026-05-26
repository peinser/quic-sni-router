import argparse
import asyncio
import subprocess
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class BackendProtocol(QuicConnectionProtocol):
    def __init__(self, *args, response_body: bytes, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._response_body = response_body

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._http.send_headers(
                    stream_id=http_event.stream_id,
                    headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
                )
                self._http.send_data(http_event.stream_id, self._response_body, end_stream=True)
                self.transmit()


def ensure_cert(cert_dir: Path, hostname: str) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert = cert_dir / f"{hostname}.crt"
    key = cert_dir / f"{hostname}.key"
    if cert.exists() and key.exists():
        return cert, key
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            f"/CN={hostname}",
            "-addext",
            f"subjectAltName=DNS:{hostname}",
        ],
        check=True,
    )
    return cert, key


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--idle-timeout", type=float, default=60.0)
    args = parser.parse_args()

    cert, key = ensure_cert(Path("/tmp/qsr-e2e-certs"), args.hostname)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.idle_timeout = args.idle_timeout
    configuration.load_cert_chain(str(cert), str(key))

    await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=lambda *a, **kw: BackendProtocol(*a, response_body=f"hello from {args.name}\n".encode(), **kw),
    )
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
