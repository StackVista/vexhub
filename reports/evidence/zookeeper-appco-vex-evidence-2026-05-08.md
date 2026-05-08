# ZooKeeper AppCo VEX Evidence - 2026-05-08

## Scope

This draft covers the HIGH findings in the latest local cve-reporter scan for
`quay.io/stackstate/zookeeper:3.9.5-7c9dc1f5-main-28`.

It intentionally scopes statements to the SUSE Observability ZooKeeper image
repositories:

- `pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper`
- `pkg:oci/zookeeper?repository_url=registry.rancher.com/suse-observability/zookeeper`

It does not VEX the upstream SUSE Application Collection source image directly.

## Inputs Reviewed

- `vexhub` base branch: `kafka-vex-security-review` at `86b2b5c7cde2ac39081d9fe002d634a199377a76`
- `helm-charts` `origin/master`: `d6017cb76c19126cfc4ee27bb00c5f5edb17928c`
- Local cve-reporter DB row for image id `263`, last seen `2026-05-08 06:48:50`
- Local image inspection of `quay.io/stackstate/zookeeper:3.9.5-7c9dc1f5-main-28`
- GitHub Advisory Database entries for `GHSA-rwm7-x88c-3g2p`, `GHSA-mj4r-2hfc-f8p6`, and `GHSA-355h-qmc2-wpwf`

## Scanner Rows

cve-reporter currently reports six active HIGH rows for the image:

| Scanner IDs | Package | Version | Runtime interpretation |
|---|---|---:|---|
| `CVE-2026-2332`, `GHSA-355h-qmc2-wpwf` | `org.eclipse.jetty:jetty-http` / `jetty-http` | `9.4.58.v20250814` | **Not VEXed.** The ZooKeeper chart starts active Jetty-backed HTTP surfaces: AdminServer and Prometheus metrics. |
| `CVE-2026-42577`, `GHSA-rwm7-x88c-3g2p` | `io.netty:netty-transport-native-epoll` / `netty-transport-native-epoll` | `4.1.130.Final` | VEX candidate: the supported chart does not configure ZooKeeper's Netty server connection factory or TLS, so no Netty epoll channel is instantiated. |
| `CVE-2026-42583`, `GHSA-mj4r-2hfc-f8p6` | `io.netty:netty-codec` / `netty-codec` | `4.1.130.Final` | VEX candidate: the supported chart does not configure a Netty pipeline or `Lz4FrameDecoder`. |

The remaining active rows are five MEDIUM rows and two LOW rows. They are left
visible in this draft.

## Primary Chart References

The chart references below use the GitHub mirror of `helm-charts` at commit
`d6017cb76c19126cfc4ee27bb00c5f5edb17928c`, fetched from `origin/master` on
2026-05-08:

- SUSE Observability includes the ZooKeeper subchart:
  [`stable/suse-observability/Chart.yaml#L44-L46`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/suse-observability/Chart.yaml#L44-L46).
- The ZooKeeper image defaults to the StackState retag and the chart command defaults to `/scripts/setup.sh`:
  [`stable/zookeeper/values.yaml#L80-L84`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/values.yaml#L80-L84),
  [`stable/zookeeper/values.yaml#L209-L217`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/values.yaml#L209-L217).
- The StatefulSet renders the chart image and command into the `zookeeper` container:
  [`stable/zookeeper/templates/statefulset.yaml#L173-L188`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/statefulset.yaml#L173-L188).
- `setup.sh` execs the SUSE image entrypoint and `zkServer.sh start-foreground`:
  [`stable/zookeeper/templates/scripts-configmap.yaml#L80-L99`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/scripts-configmap.yaml#L80-L99).
- The chart renders `zoo.cfg` itself. The default rendered config includes client/quorum settings, AdminServer, and Prometheus metrics, but it does not set `zookeeper.serverCnxnFactory` or `org.apache.zookeeper.server.NettyServerCnxnFactory`:
  [`stable/zookeeper/templates/configmap.yaml#L26-L60`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/configmap.yaml#L26-L60).
- Client and quorum TLS are explicitly disabled by default and currently marked non-functional with the SUSE Application Collection image:
  [`stable/zookeeper/values.yaml#L790-L804`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/values.yaml#L790-L804),
  [`stable/zookeeper/values.yaml#L827-L831`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/values.yaml#L827-L831).
- TLS init containers, TLS ports, TLS mounts, and TLS volumes are conditional on `tls.client.enabled` or `tls.quorum.enabled`:
  [`stable/zookeeper/templates/statefulset.yaml#L111-L169`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/statefulset.yaml#L111-L169),
  [`stable/zookeeper/templates/statefulset.yaml#L230-L246`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/statefulset.yaml#L230-L246),
  [`stable/zookeeper/templates/statefulset.yaml#L302-L311`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/statefulset.yaml#L302-L311),
  [`stable/zookeeper/templates/statefulset.yaml#L342-L357`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/statefulset.yaml#L342-L357).
- The normal Service exposes ZooKeeper TCP ports only; the metrics Service exposes the Prometheus metrics HTTP endpoint:
  [`stable/zookeeper/templates/svc.yaml#L35-L64`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/svc.yaml#L35-L64),
  [`stable/zookeeper/templates/metrics-svc.yaml#L21-L28`](https://github.com/StackVista/helm-charts/blob/d6017cb76c19126cfc4ee27bb00c5f5edb17928c/stable/zookeeper/templates/metrics-svc.yaml#L21-L28).

## Runtime Evidence

The local image contains the scanned libraries under `/usr/share/zookeeper/lib/`,
including:

- `jetty-http-9.4.58.v20250814.jar`
- `netty-codec-4.1.130.Final.jar`
- `netty-transport-native-epoll-4.1.130.Final-linux-x86_64.jar`
- `zookeeper-3.9.5.jar`
- `zookeeper-prometheus-metrics-3.9.5.jar`

The image entrypoint generates `zoo.cfg` only when the file does not already
exist. In the supported chart deployment, `zoo.cfg` is mounted from the chart
ConfigMap, so the entrypoint preserves the chart-rendered configuration and then
execs `zkServer.sh start-foreground`.

A short local startup with chart-equivalent `zoo.cfg` confirmed the runtime
posture:

```text
secureClientPort is not set
metricsProvider.className is org.apache.zookeeper.metrics.prometheus.PrometheusMetricsProvider
Started ServerConnector ... {0.0.0.0:9141}
Started AdminServer on address 0.0.0.0, port 8080 and command URL /commands
Using org.apache.zookeeper.server.NIOServerCnxnFactory as server connection factory
binding to port /0.0.0.0:2181
```

## Per-CVE Decision

### CVE-2026-2332 / GHSA-355h-qmc2-wpwf - not VEXed

The vulnerable code is Jetty's HTTP/1.1 parser for chunked transfer-extension
quoted strings. The supported ZooKeeper deployment has active Jetty-backed HTTP
surfaces:

- `admin.enableServer=true` and `admin.serverPort=8080` are rendered into
  `zoo.cfg`.
- `metricsProvider.className=org.apache.zookeeper.metrics.prometheus.PrometheusMetricsProvider`
  and its HTTP host/port are rendered when metrics are enabled.
- The metrics port is exposed by the StatefulSet and metrics Service.

That means `vulnerable_code_not_in_execute_path` is not defensible for the Jetty
HIGH. This should be fixed by an upstream AppCo image carrying Jetty `9.4.60` or
later, or by a separate product decision to disable/replace the Jetty-backed
surfaces.

### CVE-2026-42577 / GHSA-rwm7-x88c-3g2p - VEXed

The vulnerable code is in Netty's epoll transport handling of half-closed
channels after a FIN+RST sequence. Reaching it requires an active Netty epoll
channel handling untrusted network input.

The supported ZooKeeper deployment does not satisfy that condition. The chart
renders `zoo.cfg` without `zookeeper.serverCnxnFactory` or
`NettyServerCnxnFactory`, and client/quorum TLS are disabled by default. TLS
resources and ports are only rendered when those flags are enabled. The normal
ZooKeeper client/quorum traffic therefore uses the ZooKeeper NIO connection
factory rather than Netty epoll.

### CVE-2026-42583 / GHSA-mj4r-2hfc-f8p6 - VEXed

The vulnerable code is `io.netty.handler.codec.compression.Lz4FrameDecoder`
inside a Netty channel pipeline. Reaching it requires a running Netty pipeline
with that decoder installed and receiving attacker-controlled frames.

The supported ZooKeeper deployment does not configure any Netty pipeline. The
active HTTP surfaces are Jetty-backed AdminServer and Prometheus metrics, while
ZooKeeper client/quorum traffic uses the default non-TLS NIO connection factory.
No supported chart path installs or starts `Lz4FrameDecoder`.

## Review Caveats

These statements are deployment-context VEX, not claims about the SUSE
Application Collection `apache-zookeeper` image in arbitrary use.

The Netty statements should be re-reviewed if any supported SUSE Observability
deployment:

- sets `zookeeper.serverCnxnFactory` to `org.apache.zookeeper.server.NettyServerCnxnFactory`,
- enables ZooKeeper client TLS or quorum TLS,
- overrides the container command or args,
- adds a Netty-based sidecar or custom service in the ZooKeeper pod, or
- replaces the chart-rendered `zoo.cfg` with a custom configuration.

An independent security review is still required before merging these HIGH OCI
VEX statements, per `CONTRIBUTING.md`.

## Local Validation

The per-product OpenVEX files were generated with `vexctl` 0.4.1
(`vexctl create` plus `vexctl add`) and deterministic
`SOURCE_DATE_EPOCH=1778240700` (`2026-05-08T11:45:00Z`).

Validation commands:

```bash
python3 -m json.tool pkg/oci/quay.io/stackstate/zookeeper/scan.openvex.json
python3 -m json.tool pkg/oci/registry.rancher.com/suse-observability/zookeeper/scan.openvex.json
python3 tools/build_index.py --check
git diff --check
trivy image --quiet --skip-db-update --scanners vuln --severity HIGH \
  --vex pkg/oci/quay.io/stackstate/zookeeper/scan.openvex.json \
  --show-suppressed \
  quay.io/stackstate/zookeeper:3.9.5-7c9dc1f5-main-28
```

Observed Trivy behavior after the VEX file is applied:

```text
Java (jar)
==========
Total: 1 (HIGH: 1)

Remaining:
  org.eclipse.jetty:jetty-http  CVE-2026-2332  HIGH  fixed

Suppressed Vulnerabilities (Total: 2)
  io.netty:netty-codec                  CVE-2026-42583  not_affected  vulnerable_code_not_in_execute_path
  io.netty:netty-transport-native-epoll CVE-2026-42577  not_affected  vulnerable_code_not_in_execute_path
```
