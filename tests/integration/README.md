# Integration Tests

Planned coverage:

- Two QUIC/mTLS backend servers on UDP 8443.
- Golden `curl --http3` captures for known SNI routes.
- Unknown SNI drop behavior.
- First-packet parse latency and steady-state forwarding latency.

The MVP scaffold keeps this directory as the contract for future containerized integration tests.
