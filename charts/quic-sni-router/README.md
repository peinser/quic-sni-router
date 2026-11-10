# quic-sni-router Helm chart

Deploys [quic-sni-router](https://github.com/Peinser/quic-sni-router) into Kubernetes: a QUIC SNI router that accepts QUIC v1 and v2 Initial packets, reads the TLS ClientHello SNI, and forwards original datagrams unchanged to a configured backend. Backends terminate TLS/mTLS; the router holds no TLS private keys. Optional CID decoding uses separate symmetric keys.

## Install

For unencrypted QUIC-LB-capable backends, set `config.quicLb.configurations` and each route's
`quicLbServerIds` map. Hex IDs must be strings (quote leading zeros). The chart
validates basic shapes/ranges; the router also validates ID lengths, configuration
references, duplicate assignments, and rotation settings. `quicLb` and
`cidEncoding` are mutually exclusive. See [QUIC-LB configuration](../../docs/quic-lb.md)
for draft revision, key rotation, and the distinction between encryption and CID
authentication. Router-process steering remains separate work.

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

## Confidential configuration

For `cidEncoding` or encrypted QUIC-LB, provision an externally managed Kubernetes
Secret in the release namespace with the **complete** router configuration under
the key `router.yaml`. Manage it through your secret-management tooling, outside
Helm. Then set only its name in values:

```yaml
existingSecret: qsr-router-config
config:
  listen:
    udp: ":8443" # Must match listen.udp in the Secret's router.yaml.
```

This replaces the generated ConfigMap; Helm neither reads nor creates the Secret.
The Secret file is mounted read-only at `/config/router.yaml` with mode `0440`,
readable through the default pod `fsGroup`. If overriding the security context,
retain a group that can read the mounted file. The router needs no Kubernetes API
permissions. Restrict Secret access with RBAC and enable encryption at rest in the
cluster.

The file supplies all runtime settings, including routes, sessions, and CID keys;
it is not merged with `config` values. Keep `config.listen.udp` aligned with the
file because the chart uses it for container, Service, and NetworkPolicy ports.
Secret volume updates use the same hot-reload path as ConfigMaps (no `subPath`
mount). `configMap.checksumAnnotation` is ignored in Secret mode; restart pods
explicitly when changing restart-only settings.

Inline `config.cidEncoding` and QUIC-LB `key` fields are rejected, including when
using an external configuration. This keeps keys out of generated ConfigMaps and
new Helm release values. When migrating, remove old inline keys from values
(avoid `--reuse-values`), provision the Secret, and rotate keys previously stored
in ConfigMaps or Helm release history using the router's key-rotation procedure.

## How it routes

```text
WAN UDP/443 -> Service (LoadBalancer)
            -> Pod (router) -> Backend Service/Pod (UDP, terminates mTLS)
```

- `service.externalTrafficPolicy` defaults to `Cluster`. This is the standard kube-proxy behaviour — client traffic is SNAT'd to the receiving node's IP before reaching the router pod. Session pinning still works (each client→router flow gets a unique kube-proxy source port), but the router's logs will show node IPs instead of real client IPs. Set this to `Local` if you need real source IPs and your LB supports it; be aware that `Local` skips nodes without a router pod, which interacts with PodDisruptionBudget during rollouts.
- The chart defaults to two independent pods. The Service/LB balances UDP flows; pods do not share a `SO_REUSEPORT` group or connection state. NAT rebinding and replica replacement can lose routing state.
- Backends are resolved at pod startup and on every hot reload. To pick up an IP change behind a stable hostname without a config edit, run `helm upgrade --recreate-pods` or `kubectl rollout restart`.

## Policy routing (Linux)

`config.listen.fwmark` sets `SO_MARK` on the listener and all upstream UDP sockets
(IPv4 and IPv6). It defaults to `0` (disabled); valid values are decimal integers
from `0` to `4294967295`. For example:

```yaml
config:
  listen:
    fwmark: 12345
containerSecurityContext:
  capabilities:
    drop: [ALL]
    add: [NET_ADMIN] # NET_RAW is sufficient on Linux 5.17 and later
```

The chart does not grant capabilities automatically. The capability must remain
available for new upstream sockets; failures are logged and traffic is never
sent through an unmarked fallback socket. Listener marking failure aborts startup.

An administrator must separately configure matching policy rules, for example
`ip -6 rule add pref 90 fwmark 12345 lookup main` and its `ip -4` equivalent.
The rules and routes must apply in the network namespace where QSR's route lookup
occurs. Pods normally have their own network namespaces: a host WARP rule and a
pod socket mark are not automatically an end-to-end routing solution, and CNIs
may use or modify packet marks. Coordinate mark values and rules with your CNI.
The chart does not install routing rules. See the
[routing semantics and permissions](../../README.md#policy-routing-with-a-socket-mark-linux).

Changing the mark requires a pod restart. With the default
`configMap.checksumAnnotation: false`, explicitly run `kubectl rollout restart`
for the Deployment after updating the configuration, or enable checksum-based
rollouts below.

## Transparent client source (Linux)

`config.listen.transparent: true` binds every upstream socket to the client's
IP address and port, so backends see real clients instead of the router. The
[router README](../../README.md#transparent-client-source-linux) describes the
semantics and return-path recipes, and why source addresses then need
[ingress anti-spoofing](../../README.md#spoofed-client-addresses). Three
conditions decide whether it can work in a cluster; the chart takes care of the
first and leaves the other two to you:

```yaml
config:
  listen:
    transparent: true
containerSecurityContext:
  capabilities:
    drop: [ALL]
    add: [NET_RAW] # or NET_ADMIN
```

1. **Real client addresses at the pod.** With `externalTrafficPolicy: Cluster`
   (the chart default), kube-proxy rewrites client sources to node addresses.
   The router would then bind node addresses, and backend replies would go to
   those nodes instead of back to the router.

   > [!WARNING]
   > **`config.listen.transparent: true` sets the Service's
   > `externalTrafficPolicy` to `Local`**, for `LoadBalancer` and `NodePort`
   > Services, overriding `service.externalTrafficPolicy`. `helm install` and
   > `helm upgrade` print a warning saying so. Only nodes running a router pod
   > then receive traffic, which interacts with the PodDisruptionBudget during
   > rollouts; turning transparent mode off restores your
   > `service.externalTrafficPolicy`.

   A `ClusterIP` Service has no such policy. A load balancer or CNI that itself
   rewrites client sources still hides them from the router. With
   `existingSecret`, the chart cannot read the file: set
   `config.listen.transparent` to the file's value, as with `config.listen.udp`,
   so the Service policy and the warning match.
2. **The capability.** The router needs `NET_RAW` or `NET_ADMIN` and refuses to
   start without it (`IP_TRANSPARENT probe failed` in the log). The chart runs
   as UID 10001 and the image sets no file capabilities; some container
   runtimes add requested capabilities only to the bounding set of a non-root
   process, so confirm the router starts.
3. **A return path in the router pod's network namespace.** Backend replies
   are addressed to the client. A backend pod elsewhere in the cluster sends
   them through its own node toward the client, never through the router pod,
   so the README recipes do not help there. Transparent mode fits a backend
   that shares the router pod's network namespace (a sidecar reached on
   `127.0.0.1`, covered by the README source rule installed in that namespace),
   or a router on host networking with host routes. The chart installs no
   routes or rules and has no init-container or host-networking values, so
   either setup needs a post-renderer or your own manifests.

Changing the setting requires a pod restart, as with `fwmark`.

## Hot reload

This chart's `ConfigMap` is rendered from `.Values.config`. A `helm upgrade` that changes routes writes a new `ConfigMap` revision. kubelet propagates it into each pod (typically <60s) and the router's `inotify` watch atomically swaps in the new routes:

- Existing sessions to a route whose backend is **still in the new config** keep going untouched.
- Existing sessions to a route whose backend **disappeared** from the new config are evicted immediately (hard cutover).
- A parse failure or DNS-resolution failure on the new file is logged and the previous config keeps serving traffic (fail-closed).
- Reload parsing and DNS resolution run in one background worker; the dataplane publishes a successful candidate. Only completed writes and atomic replacements trigger reloads. Removed backends terminate associated flows. Startup and shutdown can still wait for the resolver.

To force a pod rotation on every `helm upgrade` instead (drops live QUIC sessions):

```yaml
configMap:
  checksumAnnotation: true
```

The following fields require a process restart and are ignored on reload with a logged warning: `config.listen.udp`, `config.listen.fwmark`, `config.listen.transparent`, `config.sessions.maxSessions`.

## Values

See [values.yaml](values.yaml) for the full schema and defaults. [values.schema.json](values.schema.json) enforces required fields and value ranges at `helm install` / `helm upgrade` time.

Highlights:

| Key | Default | Notes |
| --- | --- | --- |
| `replicaCount` | `2` | Independent pods behind the UDP Service; connection state is not shared. |
| `image.repository` | `ghcr.io/peinser/quic-sni-router` | Override for a fork or local mirror. |
| `image.tag` | `""` (uses `.Chart.appVersion`) | The publish pipeline pins this to `<version>-<sha>`. |
| `config.routes` | `{}` | Map of SNI to `{host, port}`. Empty is valid but causes every Initial to be dropped. |
| `existingSecret` | `""` | Existing Secret containing complete `router.yaml`; overrides ConfigMap settings. Required for confidential CID configuration. |
| `config.listen.fwmark` | `0` | Linux socket mark on all QSR UDP sockets; nonzero requires a capability and matching policy rules. Restart required. |
| `config.listen.transparent` | `false` | Linux: backends see the client's IP and port. **Sets the Service's `externalTrafficPolicy` to `Local`**, overriding `service.externalTrafficPolicy`. Requires a capability and a return path the chart does not install; see [Transparent client source](#transparent-client-source-linux). Restart required. |
| `service.type` | `LoadBalancer` | Use `NodePort` for bare-metal without an LB. |
| `service.externalTrafficPolicy` | `Cluster` | Standard kube-proxy behaviour. Set to `Local` to preserve the real client source IP (and skip nodes without a router pod). Ignored, and `Local` used, while `config.listen.transparent` is true. |
| `podSecurityContext` | runAsNonRoot, uid 10001, RuntimeDefault seccomp | Hardened defaults; override only with reason. |
| `containerSecurityContext` | `cap drop ALL`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false` | Default settings need no additional capabilities. Nonzero `fwmark` requires `NET_ADMIN` or, on Linux 5.17+, `NET_RAW`. `transparent: true` requires `NET_RAW` or `NET_ADMIN`. |
| `resources.limits` | memory only | No CPU limit — CFS throttling causes p99 spikes on UDP. |
| `podDisruptionBudget.enabled` | `true` | Only rendered when `replicaCount > 1`. |
| `networkPolicy.enabled` | `false` | Cluster-CNI- and namespace-specific; opt in per environment. |

## Probes and UDP

Kubelet has no native readiness/liveness probe for UDP services. The defaults are no-op. If your image bundles `iproute2`, uncomment the exec probe stub in `values.yaml`. The router process exits non-zero on a fatal error so the standard pod restart loop applies regardless.

## Security

See [SECURITY.md](../../SECURITY.md) and [docs/threat-model.md](../../docs/threat-model.md). Quick checklist before WAN exposure:

- Backends on a non-routable / cluster-internal network (the chart `Service` is `ClusterIP`-friendly out of the box for backends).
- Upstream BCP 38 / uRPF + per-source rate limit at the LB. With `config.listen.transparent`, backends see client addresses directly, so drop internal and bogon sources before they reach the router.
- Consider `service.externalTrafficPolicy: Local` if you need real client IPs and accept that LB traffic to nodes without a router pod is dropped.
- Set `networkPolicy.enabled: true` with namespace-restricted ingress.
- `serviceAccount.automount: false` (chart default) — the router needs no Kubernetes API access. With `serviceAccount.create: false` (chart default) the pod uses the namespace's `default` ServiceAccount; combined with `automount: false` no API token is mounted regardless.

## License

Apache License 2.0. Copyright 2026 Peinser BV. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE) at the repo root.
