# Kafka AppCo VEX Evidence - 2026-05-07

## Scope

This draft covers the HIGH Kafka findings seen in cve-reporter for `quay.io/stackstate/kafka:3.9.2-f6a6e1a0-main-35` and in the SUSE Application Collection `apache-kafka:3.9.2-13.5` attestation.

It intentionally scopes statements to the SUSE Observability Kafka broker image repositories:

- `pkg:oci/kafka?repository_url=quay.io/stackstate/kafka`
- `pkg:oci/kafka?repository_url=registry.rancher.com/suse-observability/kafka`

It does not VEX the upstream AppCo source image directly. The docker-images retag workflow scans that source image before copying, and temporary upstream-owned gate exceptions stay in `images/kafka/.trivyignore.yaml`.

## Inputs Reviewed

- `vexhub` base: `c949ff3f5339d11ef9ef9622038b7346eec7936f`
- `docker-images` `origin/main`: `e87c8d2fbad2abb7533778612282c5ff9e94928d`
- `helm-charts` `origin/master`: `77c420897d4eaee15dae80f4c8c8ace99cd63e96`
- Local cve-reporter query at `2026-05-07T14:45:56Z`
- User-provided AppCo attestation for `apache-kafka:3.9.2-13.5`

## Scanner Rows

cve-reporter currently reports ten HIGH rows for the Kafka image. Four are Trivy CVE rows and six are Grype GHSA rows:

| Scanner IDs | Package | Version | Runtime interpretation |
|---|---|---:|---|
| `CVE-2026-2332`, `GHSA-355h-qmc2-wpwf` | `org.eclipse.jetty:jetty-http` | `9.4.57.v20241219` | Jetty is present for Kafka distribution tooling, but SUSE Observability starts only the Kafka broker, not Kafka Connect or a Jetty REST endpoint. |
| `CVE-2025-67030`, `GHSA-6fmv-xxpf-w3cw` | `org.codehaus.plexus:plexus-utils` | `3.5.1` | The reported archive-extraction path is not used by the broker startup path. |
| `CVE-2026-24281`, `GHSA-7xrh-hqfc-g7qr` | `org.apache.zookeeper:zookeeper` | `3.8.4` | The reported ZKTrustManager hostname-verification path requires ZooKeeper client TLS, which the chart disables by default. |
| `CVE-2026-24308`, `GHSA-crhr-qqj8-rpxc` | `org.apache.zookeeper:zookeeper` | `3.8.4` | The chart does not inject ZooKeeper SASL credentials or ZooKeeper client TLS secret paths by default. |
| `CVE-2026-42577`, `GHSA-rwm7-x88c-3g2p` | `io.netty:netty-transport-native-epoll` | `4.1.125.Final` | The broker deployment does not configure ZooKeeper's Netty client socket implementation or Netty epoll. |
| `CVE-2026-42583`, `GHSA-mj4r-2hfc-f8p6` | `io.netty:netty-codec` | `4.1.125.Final` | The broker deployment does not run Netty-based services from this image. |

The AppCo attestation lists the same six underlying HIGH vulnerabilities as CVE IDs. cve-reporter shows ten HIGH rows because Trivy and Grype report several of the same advisories under different IDs.

## Deployment Evidence

The Kafka chart deploys the image as a broker StatefulSet. In `stable/kafka/templates/statefulset.yaml`, the `kafka` container runs the chart image and defaults to the chart command from `stable/kafka/values.yaml`.

The command is `/scripts/setup.sh`. In `stable/kafka/templates/scripts-configmap.yaml`, `setup.sh` finishes with:

```bash
exec /usr/share/kafka/bin/kafka-server-start.sh /usr/share/kafka/config/server.properties
```

There is no chart path that starts `connect-distributed.sh`, `connect-standalone.sh`, a Jetty-backed Kafka Connect REST worker, or Maven/Plexus archive extraction as part of the supported broker deployment.

The Kafka Service exposes Kafka TCP listener ports only. JMX metrics are provided by a separate `jmx-exporter` sidecar image and service, not by Jetty from the Kafka image.

Default Kafka auth values are plaintext for client and inter-broker protocols. `auth.zookeeper.tls.enabled` defaults to `false`, and `auth.sasl.jaas.zookeeperUser` / `auth.sasl.jaas.zookeeperPassword` default to empty strings. ZooKeeper client TLS material is copied only when `auth.zookeeper.tls.enabled` and an existing ZooKeeper TLS secret are configured.

## Review Caveats

These statements are deployment-context VEX, not an upstream claim about the SUSE Application Collection `apache-kafka` image in every possible use.

The statements should be re-reviewed if any supported SUSE Observability deployment:

- enables ZooKeeper client TLS or ZooKeeper SASL for Kafka brokers,
- uses this image for Kafka Connect,
- overrides the container command or args,
- runs plugin/archive extraction inside the broker container, or
- explicitly configures ZooKeeper's Netty client socket or Netty epoll transport.

## Local Validation

The draft file was checked with:

```bash
python3 tools/build_index.py --check
trivy image --quiet --skip-db-update --scanners vuln --severity HIGH \
  --vex pkg/oci/quay.io/stackstate/kafka/scan.openvex.json \
  --show-suppressed \
  quay.io/stackstate/kafka:3.9.2-f6a6e1a0-main-35
```

Trivy 0.70.0 reported `Total: 0 (HIGH: 0)` and showed six suppressed HIGH CVEs from the OpenVEX file: `CVE-2026-2332`, `CVE-2025-67030`, `CVE-2026-24281`, `CVE-2026-24308`, `CVE-2026-42577`, and `CVE-2026-42583`.

This validates the Trivy/OpenVEX shape. cve-reporter's Grype rows still need scanner-side alias/VEX handling if the goal is to make the combined Trivy+Grype total match the AppCo attestation count exactly.
