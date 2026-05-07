# StackVista VEX Hub

Central repository of OpenVEX (Vulnerability Exploitability eXchange)
statements about CVEs in SUSE Observability product images.

> Conventions for filing statements live in [CONTRIBUTING.md](./CONTRIBUTING.md).

## What lives here

OpenVEX statements organised under `pkg/` by PURL type. Statements
are consumed by Trivy directly via `--vex repo` and suppress
findings that genuinely don't apply to our deployment.

## Scope

VEX statements in this hub apply to SUSE Observability product
artefacts distributed as OCI images from:

- `quay.io/stackstate/*`
- `registry.rancher.com/suse-observability/*` (Rancher Prime distribution)

OCI products are identified with the same PURL shape Rancher's hub
uses: `pkg:oci/<image-name>?repository_url=<registry>/<namespace>/<image>`.

The hub is **complementary to** the SUSE-wide automated VEX
pipeline operated by Rancher's
[image-scanning](https://github.com/rancher/image-scanning) team.
Their pipeline runs `govulncheck` against listed StackVista
Go-binary repos, scans re-tagged container images, and publishes
the generated VEX statements into
[rancher/vexhub](https://github.com/rancher/vexhub) (also visible
at [scans.rancher.com](https://scans.rancher.com/)).

We focus on what their automation can't easily produce:

- **Deployment-context statements** - helm chart config, network
  policies, runtime flags that only we can attest to.
- **Java/JVM and other non-Go components** not yet covered by their
  pipeline.
- **Judgment calls** that require human security review rather than
  static analysis.

Go-source-level reachability claims that `govulncheck` can derive
belong in rancher/vexhub via the upstream pipeline, not duplicated
here. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the "is this the
right hub?" decision.

Statement scope is the SUSE Observability deployment context only.
A `not_affected` statement about Jetty in our re-tagged ZooKeeper
image is scoped to how *we* configure the chart — it makes no claim
about how SUSE Application Collection's source image behaves in
another consumer's environment. 

## Relationship to Rancher's VEX repos

Rancher keeps authoring and publication separate:

- `rancher/image-scanning` is the workflow repo where reviewed VEX
  input is validated against scanner data and generated into OpenVEX.
- `rancher/vexhub` is the published static hub consumed by Trivy and
  other VEX repository clients.

This repo currently carries SUSE Observability-specific authoring and
publication together, but the published files intentionally mirror
`rancher/vexhub`: one `pkg/.../scan.openvex.json` file per indexed
product and an `index.json` with `version: 1` plus package IDs and
locations. If a statement can be handled by Rancher's `image-scanning`
workflow, prefer that route and let their automation publish it.

## Layout

```
vexhub/
  README.md
  LICENSE                              CC-BY-4.0 (data license)
  CODEOWNERS
  CONTRIBUTING.md
  vex-repository.json                  Aqua VEX Repository v0.1 descriptor
  index.json                           VEX repository index (generated)
  pkg/                                 OpenVEX statements, organised by PURL
    maven/                             pkg:maven/...
    oci/                               pkg:oci/... (image-scoped, one file per OCI product)
    apk/, rpm/, npm/, ...              one directory per PURL type as needed
  reports/                             CSV exports for human review (future)
  docs/
    adr/                               Architecture decision records (future)
  tools/                               build_index.py + vexctl usage docs
```

Layout matches the Aqua/Rancher VEX Hub convention so consumers familiar
with `aquasecurity/vexhub` and `rancher/vexhub` find files where they
expect. `index.json` intentionally mirrors Rancher's generated index:
`version: 1` plus a `packages` list of PURL IDs and file locations.

## Consuming this hub with Trivy

Add this hub to Trivy's VEX repository configuration:

```yaml
# ~/.trivy/vex/repository.yaml
repositories:
  - name: suse-observability
    url: https://github.com/stackvista/vexhub
    enabled: true
```

Then run scans with the repo enabled:

```bash
trivy vex repo download
trivy image --vex repo --show-suppressed quay.io/stackstate/kafka:<tag>
```

Suppressed findings are annotated with the matching VEX statement and the
hub source.

The same Trivy invocation can subscribe to multiple hubs (Aqua's default,
Rancher's, this hub) — each is consulted independently and statements are
applied wherever PURLs match.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the PR flow, evidence
requirements, and approval rules.

## License

VEX data in this repository is published under
[CC-BY-4.0](./LICENSE), matching the convention used by the Rancher VEX Hub
and Aqua's VEX Hub. The associated tooling and schemas may be relicensed
separately as they land.
