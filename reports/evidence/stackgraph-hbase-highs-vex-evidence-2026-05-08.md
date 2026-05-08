# stackgraph-hbase high CVE VEX evidence

Date: 2026-05-08

Image reviewed:

- `quay.io/stackstate/stackgraph-hbase:2.5-7.14.11`

Latest cve-reporter scan:

- Scan source: local cve-reporter database and `docker exec cve_scanner python main.py --list-image-cves quay.io/stackstate/stackgraph-hbase:2.5-7.14.11`
- Helm chart: `stackstate-internal/suse-observability`
- Detection time for the image rows: `2026-05-07 16:32:59`
- High rows: 6 scanner rows, collapsing to two dependency families:
  - `com.google.protobuf:protobuf-java@2.5.0`: `CVE-2021-22569`, `GHSA-wrvw-hg22-4m67`, `CVE-2024-7254`, `GHSA-735f-pc8j-v9w8`
  - `io.netty:netty-transport-native-epoll@4.1.133.Final`: `CVE-2026-42577`, `GHSA-rwm7-x88c-3g2p`

## Decision summary

Only the Netty epoll finding is VEXed in this branch.

The protobuf findings are not VEXed. The vulnerable component is present as `/opt/hbase/lib/protobuf-java-2.5.0.jar`, and StackGraph currently keeps protobuf 2.5.0 in HBase server runtime paths for compatibility. The StackGraph build explicitly warns that protobuf cannot be overridden globally because HBase server code and coprocessors depend on protobuf 2.5.0 internals at runtime. Protobuf is also used throughout HBase RPC, WAL, procedure, and coprocessor paths. These findings should remain visible until the HBase compatibility work is done or a narrower non-reachability proof is produced.

The Netty epoll finding is VEXed with `vulnerable_code_not_present`. This is not a claim that HBase avoids Netty epoll. HBase can use Netty epoll on Linux by default. The claim is narrower: the shipped component is Netty `4.1.133.Final`, while the upstream fix discussion for `CVE-2026-42577` says only Netty 4.2 and 5.0 have the problem.

## Protobuf evidence: do not VEX

cve-reporter rows:

| Vulnerability | Scanner | Package | Path | Installed | Fixed |
| --- | --- | --- | --- | --- | --- |
| `CVE-2021-22569` | Trivy | `com.google.protobuf:protobuf-java` | `/opt/hbase/lib/protobuf-java-2.5.0.jar` | `2.5.0` | `3.16.1`, `3.18.2`, `3.19.2` |
| `GHSA-wrvw-hg22-4m67` | Grype | `protobuf-java` | `/opt/hbase/lib/protobuf-java-2.5.0.jar` | `2.5.0` | `3.16.1` |
| `CVE-2024-7254` | Trivy | `com.google.protobuf:protobuf-java` | `/opt/hbase/lib/protobuf-java-2.5.0.jar` | `2.5.0` | `3.25.5`, `4.27.5`, `4.28.2` |
| `GHSA-735f-pc8j-v9w8` | Grype | `protobuf-java` | `/opt/hbase/lib/protobuf-java-2.5.0.jar` | `2.5.0` | `3.25.5` |

Source evidence:

- `repos/stackgraph/build.gradle` documents that protobuf is not overridden globally because HBase server code and coprocessors depend on protobuf 2.5.0 internals at runtime.
- The same build file overrides protobuf only in client-only modules such as `tephra-server` and `stackgraph-console-shared`, which reinforces that the HBase server image remains a special case.
- `repos/hbase-server-sts` contains HBase server-side imports of protobuf types in RPC, WAL, procedure, and coprocessor code paths.

Upstream vulnerability summaries:

- `GHSA-wrvw-hg22-4m67` / `CVE-2021-22569`: protobuf-java parsing of crafted binary data can lead to denial of service through repeated object allocation and GC pressure.
- `GHSA-735f-pc8j-v9w8` / `CVE-2024-7254`: protobuf-java parsing of malicious nested-group payloads can trigger stack overflow and process crash.

Conclusion:

No VEX statement is authored for protobuf. The component is present and parser code is part of normal HBase runtime behavior. The next action is remediation or a dedicated HBase compatibility investigation, not suppression.

## Netty epoll evidence: VEX as vulnerable code not present

cve-reporter rows:

| Vulnerability | Scanner | Package | Path | Installed | Fixed |
| --- | --- | --- | --- | --- | --- |
| `CVE-2026-42577` | Trivy | `io.netty:netty-transport-native-epoll` | `/opt/hbase/lib/hbase-shaded-netty-4.1.14.sts.20260507.faa63e7.jar` | `4.1.133.Final` | `4.2.13.Final` |
| `GHSA-rwm7-x88c-3g2p` | Grype | `netty-transport-native-epoll` | `/opt/hbase/lib/hbase-shaded-netty-4.1.14.sts.20260507.faa63e7.jar` | `4.1.133.Final` | `4.2.13.Final` |

Runtime evidence:

- `repos/stackgraph/build.gradle` includes `org.apache.hbase.thirdparty:hbase-shaded-netty:4.1.14.sts.20260507.faa63e7` in the HBase server distribution.
- `repos/stackgraph/server-docker-images-2.5/hbase/Dockerfile` adds that distribution to the `stackgraph-hbase` image.
- `repos/hbase-server-sts/hbase-server/src/main/java/org/apache/hadoop/hbase/ipc/RpcServerFactory.java` defaults HBase RPC to `NettyRpcServer`.
- `repos/hbase-server-sts/hbase-server/src/main/java/org/apache/hadoop/hbase/util/NettyEventLoopGroupConfig.java` defaults `hbase.netty.nativetransport` to true and selects `EpollEventLoopGroup`, `EpollServerSocketChannel`, and `EpollSocketChannel` on Linux.

Because HBase may use epoll at runtime, this is intentionally not a `vulnerable_code_not_in_execute_path` statement.

Version and code-presence evidence:

- The shaded jar metadata in the image reports:

  ```text
  artifactId=netty-transport-native-epoll
  groupId=io.netty
  version=4.1.133.Final
  ```

- The same jar contains relocated 4.1 epoll classes under `org/apache/hbase/thirdparty/io/netty/channel/epoll/`.
- It does not contain `EpollIoHandler`, the 4.2 epoll implementation touched by the upstream fix PR.
- GitHub Advisory Database describes `GHSA-rwm7-x88c-3g2p` / `CVE-2026-42577` as a Netty epoll denial of service involving RST after half-closed TCP connections.
- The upstream fixing PR is `netty/netty#16689`, merged into the `4.2` branch. In that PR, the Netty maintainer explicitly states: "Only 4.2 and 5.0 have the problem."

Conclusion:

The scanner row is caused by package metadata for `netty-transport-native-epoll@4.1.133.Final`, but upstream evidence says the vulnerable implementation is limited to Netty 4.2 and 5.0. The authored VEX statement is package-level:

- Product: `pkg:maven/io.netty/netty-transport-native-epoll@4.1.133.Final`
- Vulnerability: `CVE-2026-42577`
- Alias: `GHSA-rwm7-x88c-3g2p`
- Status: `not_affected`
- Justification: `vulnerable_code_not_present`

## Verification

The VEX statement was generated with `vexctl create` using `SOURCE_DATE_EPOCH=2026-05-08T09:00:00Z`.

Index verification:

```bash
python3 tools/build_index.py
python3 tools/build_index.py --check
```

Result:

```text
index.json is in sync (3 package(s))
```

Trivy verification against the image:

```bash
trivy image --quiet --skip-db-update --scanners vuln --severity HIGH \
  --vex /tmp/stackgraph-hbase-netty.openvex.json \
  --show-suppressed \
  quay.io/stackstate/stackgraph-hbase:2.5-7.14.11
```

Result:

- `CVE-2026-42577` for `io.netty:netty-transport-native-epoll` is suppressed as `not_affected / vulnerable_code_not_present`.
- `CVE-2021-22569` and `CVE-2024-7254` for `com.google.protobuf:protobuf-java@2.5.0` remain unsuppressed.
