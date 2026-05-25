# Benchmarks

Run the synthetic dataplane CPU benchmark with:

```sh
make benchmark
```

The benchmark covers route lookup, session CID lookup, and CRYPTO frame extraction. It is intended to establish whether user-space lookup/parsing dominates before investing in any heavier kernel-bypass path.

The Linux runtime uses `epoll` plus `recvmmsg`/`sendmmsg`. An earlier `io_uring` path was synchronous (submit then wait per packet) and strictly slower than the batched syscall path; it has been removed. A proper async rewrite using multishot recv, registered buffers, and IORING_RECV_MULTISHOT is the right way to revisit and is tracked as future work.

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

## What this benchmark is and isn't

- **Is**: a CPU baseline for the user-space critical-path operations (hashing, probing, parsing).
- **Isn't**: an end-to-end test. A real production p99 latency measurement requires driving the live UDP loop (recv/process/send) under representative concurrency.

## Future work

A Linux-only loopback bench that drives the full UDP router with synthetic QUIC datagrams (matching real Initial packet shapes and realistic short-header rates) would measure end-to-end p99 at varying flow counts. Worth doing once the metrics endpoint (see [ROADMAP.md](../ROADMAP.md)) is wired so we can correlate latency with active session counts.
