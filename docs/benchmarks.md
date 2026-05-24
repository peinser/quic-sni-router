# Benchmarks

Run the synthetic dataplane CPU benchmark with:

```sh
make benchmark
```

The benchmark covers route lookup, session CID lookup, and CRYPTO frame extraction. It is intended to establish whether user-space lookup/parsing dominates before investing in any heavier kernel-bypass path.

The Linux runtime uses `epoll` plus `recvmmsg`/`sendmmsg`. An earlier `io_uring` path was synchronous (submit then wait per packet) and strictly slower than the batched syscall path; it has been removed. A proper async rewrite using multishot recv, registered buffers, and IORING_RECV_MULTISHOT is the right way to revisit and is tracked as future work.

Future benchmark work should add a Linux-only loopback benchmark that drives the full UDP router with synthetic QUIC datagrams to measure end-to-end p99 latency at varying flow counts.

Production builds should start with `-DCMAKE_BUILD_TYPE=Release`, which normally maps to `-O3 -DNDEBUG` for Clang/GCC. For dedicated Ryzen hosts, compare the default build with `-DQSR_CPU_TARGET=native -DQSR_ENABLE_LTO=ON`, or use an explicit Ryzen target such as `znver3` or `znver4` when the fleet generation is known. Keep published container images architecture-neutral unless every target host supports the selected CPU features.

Example local macOS CPU baseline from AppleClang Release build:

```text
route hash lookup            18750117.19 ops/s     53.33 ns/op
session cid lookup           95301629.66 ops/s     10.49 ns/op
crypto frame extraction      10246216.58 ops/s     97.60 ns/op
```

These numbers are not a replacement for Linux UDP-loop benchmarks, but they show current user-space lookup costs are low enough that kernel receive/send costs are likely worth measuring before adding `io_uring` complexity.
