# mTLS HTTP/3 Backends Example

This example demonstrates the intended utility of `quic-sni-router`: one UDP listener routes QUIC Initial packets by SNI to multiple backend services that terminate mTLS themselves.

Topology:

```text
curl --http3 UDP 4433 -> quic-sni-router -> Caddy rvr-a UDP 8443
curl --http3 UDP 4433 -> quic-sni-router -> Caddy rvr-b UDP 8444
```

The router does not terminate TLS and does not load private keys. The Caddy backends require client certificates signed by the example CA.

## Run

```sh
./generate-certs.sh
docker compose up --build
```

In another shell, use an HTTP/3-capable curl:

```sh
curl --http3-only -vk \
  --resolve rvr-a.flightdeck.example.test:4433:127.0.0.1 \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  https://rvr-a.flightdeck.example.test:4433/

curl --http3-only -vk \
  --resolve rvr-b.flightdeck.example.test:4433:127.0.0.1 \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  https://rvr-b.flightdeck.example.test:4433/
```

Expected responses are `hello from rvr-a` and `hello from rvr-b`.

## Notes

- This is an integration example, not a unit test.
- It depends on Docker and an HTTP/3-capable curl on the host.
- Caddy terminates mTLS on the backend. The router only decrypts QUIC Initial packets enough to read SNI and forwards original datagrams unchanged.
