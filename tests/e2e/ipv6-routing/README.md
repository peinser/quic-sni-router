# IPv6 asymmetric reply routing

Run from the repository root:

```sh
make test-e2e-ipv6-routing
```

This Linux Docker E2E test covers issues [#7](https://github.com/peinser/quic-sni-router/issues/7)
and [#8](https://github.com/peinser/quic-sni-router/issues/8), fixed by `f7a64c7`.
It reuses the HTTP/3 aioquic backend and client, with **no listen.fwmark**.

```text
client namespace                           QSR/tools namespace
lo: fd71:9::20
public: fd71:7::20 --- internal bridge --- public: fd71:7::10, UDP/443
warp:   fd71:8::20 --- internal bridge --- warp:   fd71:8::10
                                          lo: ::1, aioquic UDP/8443
```

QSR runs as the production image's unprivileged user, sharing the tools
container's network namespace. The client uses its loopback address as the
source for requests to QSR. Thus replies need a default route, rather than
matching the public link's connected prefix. The client also terminates the
simulated WARP link; no tunnel, forwarding daemon or external network is needed.

QSR's policy rules, after the kernel's local-table lookup, are:

1. Public source `fd71:7::10/128`: look up main (public default via `fd71:7::20`).
2. Look up main with `suppress_prefixlength 0` (retain connected routes, suppress default).
3. Look up table 51820 (WARP default via `fd71:8::20`, source `fd71:8::10`).

Before starting traffic, JSON `ip -6 route get` assertions verify that mark-zero
lookups without a source select WARP, while the public source, with and without
its output interface, selects public. Binding QSR to `[::]:443` is intentional:
binding to the public address alone would mask missing reply-source metadata.

Immediate-mode tcpdump captures start before the client and stop after it exits.
The flushed captures must contain public ingress, backend requests and replies,
and public replies. Every public reply must have the expected source, and no
reply to the client may appear on WARP. Capture drops fail the test. Separately,
the client validates HTTP status and the exact `hello from ipv6\n` body. QUIC
migration can make a connection succeed even with the wrong return path, so
application success alone is deliberately insufficient.

## Requirements and cleanup

Docker must support Linux IPv6 internal bridge networks. The tools/client
containers drop default capabilities and receive `NET_ADMIN` for their own
addresses/routes and `NET_RAW` for packet capture. No privileged containers,
host networking, host sysctl changes or namespace mounts are used. Missing
capabilities or IPv6 support fail the test, including in CI.

The two reserved ULA subnets above must be free in Docker's network pool; run
this target serially per daemon. Image builds need the same package/registry
access as the existing E2E suite; test traffic itself is entirely offline.
Readiness and client execution have bounded timeouts. Exit/signal traps remove
all three containers and both bridges, including captures and generated certs.
On failure, logs, IPv6 addresses/rules/all tables and decoded captures are
printed before cleanup. Docker build images/cache remain available for reuse.

## Regression sensitivity

An alternate router image can be tested without rebuilding it:

```sh
QSR_ROUTER_IMAGE=my-local-router:tag make test-e2e-ipv6-routing
```

Sensitivity was verified with a temporary image changing the `sender_flush()`
ancillary-data condition in `src/udp.c` to accept only `AF_INET`. This removes
IPv6 source/interface preservation on both sendmmsg and GSO replies, while
retaining IPv4 behavior. The repository's production source was not modified.
Both existing CTest suites still passed in that image; this test failed:
zero public replies and five WARP replies, captured with source `fd71:8::10`.
The HTTP/3 request itself succeeded through QUIC migration, demonstrating why
the independent capture assertions matter. Missing replies also fail the
positive public-reply assertion and/or the bounded client check.

The corrected image passed on Linux 6.10.14 (aarch64, Docker Desktop), recording
10 public ingress packets, 9 backend requests, 7 backend replies, 7 public
replies, zero wrong-source replies and zero WARP replies. Exact positive counts
are diagnostic only: QUIC retransmission/coalescing may change them.
