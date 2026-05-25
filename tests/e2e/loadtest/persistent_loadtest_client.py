"""
Persistent QUIC + HTTP/3 loadtest harness for tests/e2e/loadtest.

Each worker opens one QUIC connection to one SNI and repeatedly sends GET /
requests on fresh HTTP/3 streams until --duration expires. This isolates the
router's established-session forwarding behaviour from fresh-handshake/SNI
routing cost.
"""
import argparse
import asyncio
import random
import ssl
import sys
import time

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class PersistentClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._bodies: dict[int, bytearray] = {}
        self._done: dict[int, asyncio.Future[bytes]] = {}

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            stream_id = http_event.stream_id
            if isinstance(http_event, HeadersReceived):
                status = dict(http_event.headers).get(b":status")
                future = self._done.get(stream_id)
                if status != b"200" and future is not None and not future.done():
                    future.set_exception(RuntimeError(f"unexpected status {status!r}"))
            elif isinstance(http_event, DataReceived):
                self._bodies.setdefault(stream_id, bytearray()).extend(http_event.data)
                if http_event.stream_ended:
                    future = self._done.get(stream_id)
                    if future is not None and not future.done():
                        future.set_result(bytes(self._bodies.get(stream_id, b"")))

    async def get(self, authority: str, path: str, timeout: float) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()
        self._done[stream_id] = future
        self._bodies[stream_id] = bytearray()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"qsr-persistent-loadtest"),
            ],
            end_stream=True,
        )
        self.transmit()
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._done.pop(stream_id, None)
            self._bodies.pop(stream_id, None)


async def worker(snis: list[str], port: int, deadline: float, timeout: float, stats: dict) -> None:
    sni = random.choice(snis)
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = sni
    try:
        connection = connect(sni, port, configuration=cfg, create_protocol=PersistentClientProtocol)
        async with connection as protocol:
            while time.monotonic() < deadline:
                start = time.monotonic()
                try:
                    body = await protocol.get(sni, "/", timeout)
                    elapsed = time.monotonic() - start
                    expected_prefix = f"hello from {sni.split('.', 1)[0]}"
                    if body.decode().strip().startswith(expected_prefix):
                        stats["success"] += 1
                        stats["latencies"].append(elapsed)
                    else:
                        stats["misroute"] += 1
                        stats["misroute_examples"].setdefault(sni, body.decode(errors="replace").strip())
                except Exception as exc:  # noqa: BLE001
                    stats["failure"] += 1
                    name = type(exc).__name__
                    stats["fail_types"][name] = stats["fail_types"].get(name, 0) + 1
    except Exception as exc:  # noqa: BLE001
        stats["failure"] += 1
        name = type(exc).__name__
        stats["fail_types"][name] = stats["fail_types"].get(name, 0) + 1


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(p / 100.0 * len(sorted_values))
    return sorted_values[min(idx, len(sorted_values) - 1)]


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--snis", required=True, help="comma-separated SNI list")
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--duration", type=int, default=30, help="seconds")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-request seconds")
    parser.add_argument("--pass-threshold", type=float, default=0.95,
                        help="minimum success rate (0..1) for exit-0")
    args = parser.parse_args()

    snis = [s.strip() for s in args.snis.split(",") if s.strip()]
    if not snis:
        print("no SNIs", file=sys.stderr)
        return 2

    stats: dict = {
        "success": 0,
        "failure": 0,
        "misroute": 0,
        "latencies": [],
        "fail_types": {},
        "misroute_examples": {},
    }
    deadline = time.monotonic() + args.duration
    print(f"persistent loadtest: {args.concurrency} connections x {args.duration}s "
          f"across {len(snis)} SNI(s), per-request timeout {args.timeout}s")
    start = time.monotonic()
    workers = [worker(snis, args.port, deadline, args.timeout, stats) for _ in range(args.concurrency)]
    await asyncio.gather(*workers)
    elapsed = time.monotonic() - start

    total = stats["success"] + stats["failure"] + stats["misroute"]
    success_rate = stats["success"] / total if total > 0 else 0.0
    latencies = sorted(stats["latencies"])

    print(f"  total requests:   {total}")
    print(f"  success:          {stats['success']} ({success_rate:.2%})")
    print(f"  failure:          {stats['failure']}")
    print(f"  misroute:         {stats['misroute']}")
    print(f"  throughput:       {total / elapsed:.1f} req/s")
    if latencies:
        print(f"  latency p50:      {percentile(latencies, 50) * 1000:.1f}ms")
        print(f"  latency p95:      {percentile(latencies, 95) * 1000:.1f}ms")
        print(f"  latency p99:      {percentile(latencies, 99) * 1000:.1f}ms")
        print(f"  latency max:      {percentile(latencies, 100) * 1000:.1f}ms")
    if stats["fail_types"]:
        print(f"  failure types:    {stats['fail_types']}")
    if stats["misroute_examples"]:
        print("  misroute samples:")
        for sni, body in list(stats["misroute_examples"].items())[:3]:
            print(f"    {sni} -> {body!r}")

    if stats["misroute"] > 0:
        print(f"FAIL: {stats['misroute']} misrouted responses (zero tolerance)")
        return 1
    if success_rate < args.pass_threshold:
        print(f"FAIL: success rate {success_rate:.2%} < threshold {args.pass_threshold:.2%}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
