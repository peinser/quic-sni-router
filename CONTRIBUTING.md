# Contributing

Thanks for considering a contribution.

## Quick start

```sh
make build        # compile router + tests (Debug)
make test         # unit tests
make sanitize     # ASAN + UBSAN unit run
make fuzz-smoke   # libFuzzer smoke (100 runs / harness)
make benchmark    # synthetic CPU benchmarks
make test-e2e     # Docker HTTP/3 SNI routing test (v1 + v2)
make test-e2e-reload  # Docker hot-reload test
make lint         # clang-tidy + cppcheck
```

The [.devcontainer/](.devcontainer/) directory has a fully configured environment (Clang 18, GCC 13, libssl, libyaml, libFuzzer runtime, Docker-in-Docker). If you use VS Code, "Reopen in Container" should be all you need.

## Layout

```
include/qsr/    public headers — every module exposes a small C API here
src/            implementation, one .c per module
tests/unit/     CTest-driven unit suites
tests/fuzz/     libFuzzer harnesses (parser surfaces)
tests/bench/    synthetic CPU benchmarks
tests/e2e/      Docker-based end-to-end tests (real aioquic clients)
charts/         Helm chart (published to Harbor on push to main)
docs/           threat model, protocol notes, examples, inspirations
.github/        CI + image + helm publish workflows
```

Read [docs/protocol-notes.md](docs/protocol-notes.md) and [docs/threat-model.md](docs/threat-model.md) before changing the dataplane.

## What we expect in a PR

- **Tests for new behaviour.** If you touch a parser, add a fuzz seed or a unit case. If you change routing or session lifecycle, add a case to the relevant `test_*.c`. If you change a security-relevant invariant, mention it in [docs/threat-model.md](docs/threat-model.md).
- **All of `make test`, `make sanitize`, `make lint` green.** CI runs these on every push; please run them locally first.
- **No new compiler warnings.** We compile with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror` on both Clang and GCC.
- **Conservative on dependencies.** New runtime dependencies need a strong reason — the production image is intentionally small (OpenSSL libcrypto + libyaml + glibc, that's it). Build-time deps are cheaper but still worth justifying.

## Code style

- C23. `-std=gnu23`. `clang-format` config in [.clang-format](.clang-format); run `make format` before committing.
- Use `[[nodiscard]]` on every fallible-returning API in headers.
- Use `nullptr`, not `NULL`.
- Don't add comments that restate what the code does. Comments should explain a non-obvious WHY — a hidden constraint, a subtle invariant, a workaround tied to a specific bug.
- Headers carry brief module-purpose comments at the top.
- Public APIs go in `include/qsr/*.h`; internal helpers stay `static` in the corresponding `.c`.

## Security-sensitive paths

- `src/quic_initial.c`, `src/quic_crypto.c`, `src/quic_frames.c`, `src/tls_client_hello.c` — anything that parses untrusted bytes. Changes here MUST have unit coverage for negative cases and SHOULD extend or update a fuzz harness.
- `src/route_table.c`, `src/session_table.c` — touched by every packet. Performance changes here need a benchmark.
- `src/runtime.c` — hot reload. Changes here SHOULD be exercised by [tests/e2e/reload/run.sh](tests/e2e/reload/run.sh).

## Reporting vulnerabilities

Privately to the maintainers — see [SECURITY.md](SECURITY.md). Please don't open a public GitHub issue for unpatched security bugs.

## Commit messages

Conventional plain prose. Subject line ≤72 chars in the imperative mood. Body explains the WHY when it's not obvious. Reference related issues by number.

```
Drop oversized client Initial datagrams before HKDF

RFC 9000 §14.1 requires clients to pad Initial-bearing UDP datagrams
to at least 1200 bytes. Anything shorter is either a probe or a
spoofed reflection attempt; either way we shouldn't burn CPU on it.

Closes #42.
```

## Licensing

By contributing, you agree your contributions are licensed under the same Apache License 2.0 as the rest of the project ([LICENSE](LICENSE)). No CLA required.
