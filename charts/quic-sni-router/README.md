# quic-sni-router Helm chart

Deploys [quic-sni-router](https://github.com/Peinser/quic-sni-router) into Kubernetes: a QUIC SNI router that accepts QUIC v1 and v2 Initial packets, reads the TLS ClientHello SNI, and forwards original datagrams unchanged to a configured backend. Backends terminate TLS/mTLS; the router holds no private keys.

## Install

```sh
helm install qsr oci://harbor.peinser.com/library/charts/quic-sni-router \
  --version <chart-version> \
  --namespace tower-system \
  --create-namespace \
  -f values.yaml
```

A minimal `values.yaml`:

```yaml
config:
  routes:
    rvr-a.flightdeck.tower.peinser.com:
      host: flightdeck-rvr-a.tower-system.svc.cluster.local
      port: 8443
    rvr-b.flightdeck.tower.peinser.com:
      host: flightdeck-rvr-b.tower-system.svc.cluster.local
      port: 8444
```

To upgrade routes in place (no pod restart, no in-flight session loss for routes whose backend was preserved):

```sh
helm upgrade qsr oci://harbor.peinser.com/library/charts/quic-sni-router \
  --version <chart-version> --reuse-values \
  --set config.routes.<sni-with\\.escaped\\.dots>.host=...
```

## How it routes

```text
WAN UDP/443 -> Service (LoadBalancer)
            -> Pod (router) -> Backend Service/Pod (UDP, terminates mTLS)
```

- `service.externalTrafficPolicy` defaults to `Cluster`. This is the standard kube-proxy behaviour — client traffic is SNAT'd to the receiving node's IP before reaching the router pod. Session pinning still works (each client→router flow gets a unique kube-proxy source port), but the router's logs will show node IPs instead of real client IPs. Set this to `Local` if you need real source IPs and your LB supports it; be aware that `Local` skips nodes without a router pod, which interacts with PodDisruptionBudget during rollouts.
- Multiple replicas share the listening port via `SO_REUSEPORT`. The chart deploys a `Deployment` with `replicas: 2` by default.
- Backends are resolved at pod startup and on every hot reload. To pick up an IP change behind a stable hostname without a config edit, run `helm upgrade --recreate-pods` or `kubectl rollout restart`.

## Hot reload

This chart's `ConfigMap` is rendered from `.Values.config`. A `helm upgrade` that changes routes writes a new `ConfigMap` revision. kubelet propagates it into each pod (typically <60s) and the router's `inotify` watch atomically swaps in the new routes:

- Existing sessions to a route whose backend is **still in the new config** keep going untouched.
- Existing sessions to a route whose backend **disappeared** from the new config are evicted immediately (hard cutover).
- A parse failure or DNS-resolution failure on the new file is logged and the previous config keeps serving traffic (fail-closed).

To force a pod rotation on every `helm upgrade` instead (drops live QUIC sessions):

```yaml
configMap:
  checksumAnnotation: true
```

The following fields require a process restart and are ignored on reload with a logged warning: `config.listen.udp`, `config.sessions.maxSessions`.

## Values

See [values.yaml](values.yaml) for the full schema and defaults. [values.schema.json](values.schema.json) enforces required fields and value ranges at `helm install` / `helm upgrade` time.

Highlights:

| Key | Default | Notes |
| --- | --- | --- |
| `replicaCount` | `2` | Multiple replicas share UDP/443 via `SO_REUSEPORT`. |
| `image.repository` | `harbor.peinser.com/library/quic-sni-router` | Override for a fork or local mirror. |
| `image.tag` | `""` (uses `.Chart.appVersion`) | The publish pipeline pins this to `<version>-<sha>`. |
| `config.routes` | `{}` | Map of SNI to `{host, port}`. Empty is valid but causes every Initial to be dropped. |
| `service.type` | `LoadBalancer` | Use `NodePort` for bare-metal without an LB. |
| `service.externalTrafficPolicy` | `Cluster` | Standard kube-proxy behaviour. Set to `Local` to preserve the real client source IP (and skip nodes without a router pod). |
| `podSecurityContext` | runAsNonRoot, uid 10001, RuntimeDefault seccomp | Hardened defaults; override only with reason. |
| `containerSecurityContext` | `cap drop ALL`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false` | The router does not need any capability beyond UDP socket on the pod-side port. |
| `resources.limits` | memory only | No CPU limit — CFS throttling causes p99 spikes on UDP. |
| `podDisruptionBudget.enabled` | `true` | Only rendered when `replicaCount > 1`. |
| `networkPolicy.enabled` | `false` | Cluster-CNI- and namespace-specific; opt in per environment. |

## Probes and UDP

Kubelet has no native readiness/liveness probe for UDP services. The defaults are no-op. If your image bundles `iproute2`, uncomment the exec probe stub in `values.yaml`. The router process exits non-zero on a fatal error so the standard pod restart loop applies regardless.

## Security

See [SECURITY.md](../../SECURITY.md) and [docs/threat-model.md](../../docs/threat-model.md). Quick checklist before WAN exposure:

- Backends on a non-routable / cluster-internal network (the chart `Service` is `ClusterIP`-friendly out of the box for backends).
- Upstream BCP 38 / uRPF + per-source rate limit at the LB.
- Consider `service.externalTrafficPolicy: Local` if you need real client IPs and accept that LB traffic to nodes without a router pod is dropped.
- Set `networkPolicy.enabled: true` with namespace-restricted ingress.
- `serviceAccount.automount: false` (chart default) — the router needs no Kubernetes API access. With `serviceAccount.create: false` (chart default) the pod uses the namespace's `default` ServiceAccount; combined with `automount: false` no API token is mounted regardless.

## License

Apache License 2.0. Copyright 2026 Peinser BV. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE) at the repo root.
