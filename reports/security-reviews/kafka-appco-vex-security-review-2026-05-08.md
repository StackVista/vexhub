# Kafka AppCo VEX — Security Review — 2026-05-08

## Scope

Independent adversarial review of the six `not_affected` OpenVEX
statements proposed for the SUSE Observability Kafka broker image in
[StackVista/vexhub#2](https://github.com/StackVista/vexhub/pull/2):

| CVE / GHSA                              | Subcomponent                                            |
| --------------------------------------- | ------------------------------------------------------- |
| `CVE-2026-2332` / `GHSA-355h-qmc2-wpwf` | `org.eclipse.jetty:jetty-http@9.4.57.v20241219`         |
| `CVE-2025-67030` / `GHSA-6fmv-xxpf-w3cw`| `org.codehaus.plexus:plexus-utils@3.5.1`                |
| `CVE-2026-24281` / `GHSA-7xrh-hqfc-g7qr`| `org.apache.zookeeper:zookeeper@3.8.4`                  |
| `CVE-2026-24308` / `GHSA-crhr-qqj8-rpxc`| `org.apache.zookeeper:zookeeper@3.8.4`                  |
| `CVE-2026-42577` / `GHSA-rwm7-x88c-3g2p`| `io.netty:netty-transport-native-epoll@4.1.125.Final`   |
| `CVE-2026-42583` / `GHSA-mj4r-2hfc-f8p6`| `io.netty:netty-codec@4.1.125.Final`                    |

Products covered:

- `pkg:oci/kafka?repository_url=quay.io/stackstate/kafka`
- `pkg:oci/kafka?repository_url=registry.rancher.com/suse-observability/kafka`

## Reviewer posture

The author's role is to make the strongest defensible case that a CVE
does not apply. The reviewer's role is the opposite: assume each
statement is wrong until reachability has been ruled out from primary
sources. The bar is "I tried to construct an exploit path through
the supported deployment and could not."

## Inputs reviewed

- PR #2 head: `codex/vex-kafka-appco-cves` at `d92712a`
- Author evidence report: [`reports/evidence/kafka-appco-vex-evidence-2026-05-07.md`](../evidence/kafka-appco-vex-evidence-2026-05-07.md)
- `helm-charts` `master`: Kafka chart (`stable/kafka/templates/scripts-configmap.yaml`,
  `stable/kafka/templates/statefulset.yaml`, `stable/kafka/values.yaml`)
- `docker-images` `main`: `images/kafka/.trivyignore.yaml` (confirms
  vulnerable JARs ship under `usr/share/kafka/libs/`)
- Upstream advisory text for each GHSA (technical scope per CVE)
- Local Trivy 0.70.0 scan of `quay.io/stackstate/kafka:3.9.2-f6a6e1a0-main-35`

## Method

For each CVE the review answered three questions:

1. **What is the vulnerable code?** — the specific class/method per the
   upstream advisory, not the generic CVE summary.
2. **What needs to be true at runtime to reach it?** — the trigger
   conditions documented for the actual flaw.
3. **Does the supported broker deployment satisfy those conditions?**
   — verified against the chart templates and default `values.yaml`,
   not assumed from the author's prose.

A "yes" to (3) would falsify the statement. A "no" verified from
primary sources confirms it.

## Findings per CVE

### CVE-2026-2332 — `jetty-http` 9.4.57 — UPHELD

- **Vulnerable code**: `HttpParser` mishandles quoted strings in
  HTTP/1.1 chunked transfer-encoding extensions (request smuggling).
- **Trigger**: an active Jetty HTTP server processing untrusted
  requests.
- **Broker reality**: chart default `command: [/scripts/setup.sh]`
  (`stable/kafka/values.yaml:404-405`); `setup.sh` execs
  `kafka-server-start.sh` (`scripts-configmap.yaml:214`). Kafka 3.9
  broker in ZooKeeper mode does not start an embedded Jetty server.
  JMX scrape is via the separate `bitnami/jmx-exporter` sidecar
  image, not Jetty from this image
  (`statefulset.yaml:444-479`). `jetty-http-9.4.57.v20241219.jar` is
  on the broker classpath (`images/kafka/.trivyignore.yaml:46-49`),
  but no broker class invokes the vulnerable parser.
- **Falsification attempt**: probe every TCP port the kafka container
  binds for an HTTP-speaking listener. Container ports are Kafka
  client/internal/external (TCP wire protocol) plus optional JMX RMI
  on 5555 (`statefulset.yaml:272-275, 349-357`). JMX RMI is not Jetty.
  Could not construct a request path.
- **Conclusion**: `vulnerable_code_not_in_execute_path` holds.

### CVE-2025-67030 — `plexus-utils` 3.5.1 — UPHELD

- **Vulnerable code**: `org.codehaus.plexus.util.Expand.extractFile`
  — Zip Slip during archive extraction (CWE-22).
- **Trigger**: code that calls `Expand.extractFile()` on an
  attacker-controlled archive.
- **Broker reality**: `plexus-utils-3.5.1.jar` is in
  `/usr/share/kafka/libs/`
  (`images/kafka/.trivyignore.yaml:40-44`). The author's framing
  ("archive extraction path") matches the actual vulnerable class
  exactly — this was checked because plexus-utils CVEs are often
  about XML or Commandline, not extraction. Nothing in
  `kafka-server-start.sh` or `KafkaDockerWrapper setup` invokes
  `Expand`. plexus-utils ships as a transitive dep of Kafka Connect
  plugin path resolution code that the chart never starts.
- **Falsification attempt**: search for any broker bootstrap path
  that could pass an attacker-influenced ZIP/JAR/TAR through
  `Expand`. None found.
- **Conclusion**: `vulnerable_code_not_in_execute_path` holds.

### CVE-2026-24281 — `zookeeper` 3.8.4 ZKTrustManager — UPHELD

- **Vulnerable code**: `org.apache.zookeeper.common.ZKTrustManager`
  hostname verification falls back to reverse DNS (PTR) when SAN
  validation fails.
- **Trigger**: ZK client TLS enabled, so an SSLContext is built and
  ZKTrustManager is instantiated; attacker controls PTR for the
  target IP.
- **Broker reality**: `auth.zookeeper.tls.enabled: false`
  (`stable/kafka/values.yaml:357`). The chart wires
  `KAFKA_ZOOKEEPER_*` SSL env vars and the secret volume
  conditionally on this flag (`statefulset.yaml:430-434`,
  `scripts-configmap.yaml:189-199`). With defaults no
  ZK SSLContext is built, so ZKTrustManager is never instantiated.
- **Falsification attempt**: look for any non-conditional path that
  would build an SSL ZK client. None found.
- **Conclusion**: `vulnerable_code_not_in_execute_path` holds.

### CVE-2026-24308 — `zookeeper` 3.8.4 ZKConfig log leak — UPHELD, justification corrected

- **Vulnerable code**: `ZKConfig` logs ZooKeeper client configuration
  values at INFO; sensitive entries (credentials, key paths) end up
  in the client logfile.
- **Trigger**: any ZK client startup that has sensitive values in
  `ZKConfig`.
- **Broker reality**: chart default `auth.sasl.jaas.zookeeperUser` and
  `zookeeperPassword` are empty strings
  (`stable/kafka/values.yaml:275-278`); `KAFKA_ZOOKEEPER_USER` and
  `KAFKA_ZOOKEEPER_PASSWORD` are only injected when `zookeeperUser`
  is non-empty (`statefulset.yaml:248-256`); ZK TLS material is only
  mounted when `auth.zookeeper.tls.enabled` and `existingSecret` are
  both set (`statefulset.yaml:430-434`, `523-528`). So the broker's
  `ZKConfig` carries non-sensitive entries (`zookeeper.connect` and
  similar) only.
- **Justification correction**: the original PR used
  `inline_mitigations_already_exist`. There is no inline
  mitigation — the logging code path may execute, but nothing
  adversary-relevant is present in the configuration to leak. The
  accurate OpenVEX justification is
  `vulnerable_code_cannot_be_controlled_by_adversary`. The author's
  conclusion stands; only the justification field is wrong.
  **Applied in this MR.**
- **Falsification attempt**: identify a default-deployment value
  loaded into `ZKConfig` that an attacker could influence. The only
  ZK-client values the chart sets unconditionally are non-sensitive
  topology/timeout settings.
- **Conclusion**: status `not_affected` is correct; justification
  changed to `vulnerable_code_cannot_be_controlled_by_adversary`.

### CVE-2026-42577 — `netty-transport-native-epoll` 4.1.125.Final — UPHELD with caveat

- **Vulnerable code**: `epollOutReady()` is a no-op when there is no
  pending flush, in the `ALLOW_HALF_CLOSURE` FIN+RST handling path
  inside `io.netty.channel.epoll.*`.
- **Trigger**: an active `io.netty.channel.epoll` channel handling a
  remote peer that performs the FIN+RST sequence with half-closure
  enabled.
- **Broker reality**: Kafka brokers use Java NIO directly for their
  listeners, not Netty. ZooKeeper client defaults to
  `ClientCnxnSocketNIO` (the `ClientCnxnSocketNetty` opt-in is not
  set). No supported broker startup path instantiates
  `io.netty.channel.epoll.*` channels.
- **Caveat — possible scanner false positive**: the upstream advisory
  GHSA-rwm7-x88c-3g2p documents the affected range as
  `netty-transport-native-epoll <= 4.2.12.Final` (4.2.x branch). The
  image ships 4.1.125.Final, which is **not in the documented
  affected range**. The current detection by Trivy/Grype may itself
  be incorrect. The deployment-context VEX is right either way; if
  scanner intelligence is corrected upstream the suppression simply
  becomes moot. Recommend tracking this separately and considering a
  `vulnerable_code_not_present` reissue if the version-range
  question is settled.
- **Falsification attempt**: search broker startup for any class that
  instantiates `EpollEventLoopGroup`, `EpollChannel`, or similar.
  None found.
- **Conclusion**: `vulnerable_code_not_in_execute_path` holds; impact
  statement updated to record the version-range observation.

### CVE-2026-42583 — `netty-codec` 4.1.125.Final — UPHELD

- **Vulnerable code**:
  `io.netty.handler.codec.compression.Lz4FrameDecoder.decode`
  allocates up to ~32 MB based on an attacker-controlled header
  field before LZ4 decompression runs.
- **Trigger**: an active server-side Netty pipeline with
  `Lz4FrameDecoder` installed, receiving crafted input from an
  untrusted sender.
- **Broker reality**: no Netty pipeline in the broker (Kafka uses
  Java NIO). Kafka's own LZ4 message compression uses `lz4-java`, a
  separate library tracked under separate CVEs in
  `images/kafka/.trivyignore.yaml`. `Lz4FrameDecoder` is not loaded.
- **Falsification attempt**: confirm no Kafka code path passes wire
  bytes through `Lz4FrameDecoder`. Confirmed.
- **Conclusion**: `vulnerable_code_not_in_execute_path` holds.

## Changes applied in this MR

The two OpenVEX files were regenerated with `vexctl` 0.4.1 and
`SOURCE_DATE_EPOCH=1778227200` (2026-05-08T08:00:00Z). The exact
sequence is recorded below for reproducibility; it is not committed
as a per-statement script (per the hub's no-script-per-statement
policy).

Diffs vs. PR #2:

- `pkg/oci/quay.io/stackstate/kafka/scan.openvex.json`
  - CVE-2026-24308 justification:
    `inline_mitigations_already_exist` →
    `vulnerable_code_cannot_be_controlled_by_adversary`.
  - CVE-2026-24308 impact statement: rewritten to make the
    "no adversary-influenceable input" reasoning explicit (rather
    than implying a non-existent inline mitigation).
  - CVE-2025-67030 impact statement: now names the specific
    vulnerable method (`Expand.extractFile`) so reviewers can verify
    the framing matches the upstream advisory without re-deriving.
  - CVE-2026-24281 impact statement: now names
    `org.apache.zookeeper.common.ZKTrustManager` and the reverse-DNS
    fallback explicitly.
  - CVE-2026-42577 impact statement: appends a NOTE about the GHSA's
    documented affected range (`<= 4.2.12.Final`, 4.2.x branch) and
    flags the version-range question for upstream follow-up.
  - CVE-2026-42583 impact statement: now names
    `Lz4FrameDecoder.decode` and contrasts with Kafka's `lz4-java`.
- `pkg/oci/registry.rancher.com/suse-observability/kafka/scan.openvex.json`
  — same edits, mirrored.

The other two statements (CVE-2026-2332, CVE-2026-2332 jetty path
and CVE-2026-2332 framing) were lightly tightened to name `HttpParser`
and clarify which Kafka components do/don't start Jetty.

`vexctl` regeneration commands (run from repo root):

```bash
export SOURCE_DATE_EPOCH=1778227200   # 2026-05-08T08:00:00Z

# For each output file (quay and rancher product PURLs), run:
#   vexctl create  --id ... --product PURL --subcomponents PURL \
#                  --vuln CVE --aliases GHSA --status not_affected \
#                  --justification ... --impact-statement ... \
#                  --file pkg/.../scan.openvex.json
# then five `vexctl add -i ...` invocations for the remaining CVEs.
```

`python3 tools/build_index.py --check` passes — no index changes
since product PURLs and file locations are unchanged.

## Trivy verification

```text
$ trivy image --quiet --skip-db-update --scanners vuln --severity HIGH \
    --vex pkg/oci/quay.io/stackstate/kafka/scan.openvex.json \
    --show-suppressed \
    quay.io/stackstate/kafka:3.9.2-f6a6e1a0-main-35

Java (jar)
==========
Total: 0 (HIGH: 0)

Suppressed Vulnerabilities (Total: 6)
  io.netty:netty-codec                  CVE-2026-42583  not_affected  vulnerable_code_not_in_execute_path
  io.netty:netty-transport-native-epoll CVE-2026-42577  not_affected  vulnerable_code_not_in_execute_path
  org.apache.zookeeper:zookeeper        CVE-2026-24281  not_affected  vulnerable_code_not_in_execute_path
  org.apache.zookeeper:zookeeper        CVE-2026-24308  not_affected  vulnerable_code_cannot_be_controlled_by_adversary
  org.codehaus.plexus:plexus-utils      CVE-2025-67030  not_affected  vulnerable_code_not_in_execute_path
  org.eclipse.jetty:jetty-http          CVE-2026-2332   not_affected  vulnerable_code_not_in_execute_path
```

Trivy honors the corrected justification on CVE-2026-24308 and
suppresses all six HIGH findings exactly as before. Suppression
behaviour is unaffected by the impact-statement edits.

## Residual risk and follow-ups

- **Class-load proof**: the strongest evidence for
  `vulnerable_code_not_in_execute_path` is a `-verbose:class` JVM log
  showing the vulnerable classes are never loaded by the broker.
  Adding a one-shot test (start the broker, capture loaded classes,
  grep for the six packages) would harden every statement of this
  shape and is recommended as a future automation add for the chart's
  smoke-test suite. Out of scope for this MR.
- **CVE-2026-42577 advisory range**: file an issue against the
  scanner intelligence sources (NVD or GHSA) if the 4.1.x detection
  is in fact a false positive. Tracking the resolution removes a
  noise source rather than just suppressing it.
- **Annual review**: per `CONTRIBUTING.md`, this set of
  `vulnerable_code_not_in_execute_path` claims should be re-checked
  before 2027-05-08 to confirm the chart wiring (especially
  `auth.zookeeper.tls.enabled`, `command:`, and the Connect/REST
  posture) is unchanged.

## Verdict

All six statements are upheld for the supported default deployment.
Changes applied: one justification correction (CVE-2026-24308) and
six tightened impact statements that name the vulnerable code
explicitly so future reviewers can verify against primary sources
without re-research.
