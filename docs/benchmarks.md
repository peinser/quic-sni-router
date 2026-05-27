# Benchmarks

Run the synthetic dataplane CPU benchmark with:

```sh
make benchmark
```

The benchmark covers route lookup, session CID lookup, and CRYPTO frame extraction. It is intended to establish whether user-space lookup/parsing dominates before investing in any heavier kernel-bypass path.

The Linux runtime uses raw-syscall `io_uring` multishot `recvmsg` with a provided-buffer ring plus `sendmmsg` send batching.

Future benchmark work should add a Linux-only loopback benchmark that drives the full UDP router with synthetic QUIC datagrams to measure end-to-end p99 latency at varying flow counts.

Production builds should start with `-DCMAKE_BUILD_TYPE=Release`, which normally maps to `-O3 -DNDEBUG` for Clang/GCC. For dedicated Ryzen hosts, compare the default build with `-DQSR_CPU_TARGET=native -DQSR_ENABLE_LTO=ON`, or use an explicit Ryzen target such as `znver3` or `znver4` when the fleet generation is known. Keep published container images architecture-neutral unless every target host supports the selected CPU features.

## Reference numbers

Linux/aarch64 Debian 13 in the devcontainer, Release build with Clang 18, 5 runs and median reported. All "ops/s" figures are for in-process micro-operations against pre-populated tables, not full datagram processing.

```text
route hash lookup            ~19 M ops/s     ~52 ns/op
session cid lookup           ~50 M ops/s     ~20 ns/op
crypto frame extraction      ~8  M ops/s    ~125 ns/op
```

Two things to note when reading these vs older snapshots:

- **Session CID lookup is ~2x slower than the pre-SipHash baseline (~10 ns/op with FNV-1a).** This is the cost of swapping FNV for SipHash-2-4 to defeat hash-flooding attacks on the open-addressed table. Net trade is correct: ~10 ns of additional CPU per session lookup, in exchange for collision-forcing becoming cryptographically infeasible. See [threat-model.md](threat-model.md).
- **The bench measures pre-populated-table lookup paths.** It does not measure the per-packet hot-path peek (`learn_long_header_cids` / `lookup_rebound_initial`) optimisations or the combined-walk insert (`qsr_session_table_put`); those are quantified by reasoning about the eliminated work (~10 ns/packet steady-state for the peek, ~2x fewer hashes per insert).

## Docker loadtest results

The Docker loadtest is a correctness-under-load harness, not a production benchmark. It is still useful for relative comparisons because it can run the same aioquic client and mock backends either through the router or directly.

Two modes exist:

- Fresh-connection mode (`loadtest_client.py`): every request opens a new QUIC + HTTP/3 connection. This stresses Initial decryption, SNI extraction, route lookup, and session-table insertion.
- Persistent mode (`QSR_LOADTEST_PERSISTENT=1`): every worker opens one QUIC connection and repeatedly sends HTTP/3 requests on new streams. This mostly stresses established-session forwarding.

Reference results from the local Docker/aarch64 environment after the backend-DCID routing fix:

| Mode | Backends | Workers | Path | Result |
| --- | ---: | ---: | --- | --- |
| Fresh connections | 2 | 10 | Router | `2833/2833`, 0 failures, 93.5 req/s |
| Fresh connections | 2 | 10 | Direct | `2947/2947`, 0 failures, 97.9 req/s |
| Fresh connections | 10 | 10 | Router | `2734/2734`, 0 failures, 90.9 req/s |
| Persistent sessions | 2 | 10 | Router | `211127/211127`, 0 failures, 7011.4 req/s |
| Persistent sessions | 2 | 10 | Direct | `240408/240408`, 0 failures, 7982.2 req/s |

Before the backend-DCID fix, the same 2-backend fresh-connection routed test collapsed to roughly 13 req/s with timeouts, while direct stayed near 98 req/s. That regression was not crypto cost; it was incorrect backend return routing through an ambiguous shared backend tuple.

Current Linux `io_uring` multishot results from the local Docker/aarch64 environment with 10 backends, 10 workers, and 10s duration:

| Mode | Result |
| --- | ---: |
| Fresh connections | 95.9 req/s, 100% success, 0 misroutes |
| Persistent sessions | 8495.7 req/s, 100% success, 0 misroutes |

Treat this as a correctness check and a direction signal, not a production benchmark.

Useful commands:

```sh
make test-loadtest
QSR_LOADTEST_DIRECT=1 make test-loadtest
QSR_LOADTEST_PERSISTENT=1 make test-loadtest
QSR_LOADTEST_PERSISTENT=1 QSR_LOADTEST_DIRECT=1 make test-loadtest
QSR_LOADTEST_BACKENDS=2 QSR_LOADTEST_CONCURRENCY=10 make test-loadtest
QSR_LOADTEST_PACKET_DEBUG=1 make test-loadtest
```

## What this benchmark is and isn't

- **Is**: a CPU baseline for the user-space critical-path operations (hashing, probing, parsing).
- **Isn't**: an end-to-end test. A real production p99 latency measurement requires driving the live UDP loop (recv/process/send) under representative concurrency.

## Future work

A Linux-only loopback bench that drives the full UDP router with synthetic QUIC datagrams (matching real Initial packet shapes and realistic short-header rates) would measure end-to-end p99 at varying flow counts. Worth doing once the metrics endpoint (see [ROADMAP.md](../ROADMAP.md)) is wired so we can correlate latency with active session counts.

Known performance gaps to close before stronger production performance claims:

- Quantify the resolved backend-address hash index under large route counts and high backend-return packet rates.
- Add dataplane counters for tuple hits, CID hits, backend-DCID hits, Initial decrypts, drops, pending-Initial evictions, session pressure evictions, incremental-expiry work, send failures, and socket-buffer clamp results.
- Add an end-to-end loopback benchmark outside Docker to separate router cost from Python/aioquic backend cost.
