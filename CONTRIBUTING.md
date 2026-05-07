# Contributing to the StackVista VEX Hub

This hub holds OpenVEX statements about CVEs in SUSE Observability
product images.

## Is this the right hub for the statement?

Before authoring, check whether your CVE is already (or should be)
covered by an upstream VEX pipeline:

- **[rancher/image-scanning](https://github.com/rancher/image-scanning)** —
  Rancher's automated pipeline scans listed StackVista Go-binary
  repos with `govulncheck` and publishes the generated VEX
  statements into [rancher/vexhub](https://github.com/rancher/vexhub).
  It is also being extended to scan our re-tagged container images.
  If your CVE is in a Go module that pipeline already covers (or
  could cover by adding the repo to its `vex/repos.txt`), defer
  there — don't duplicate the statement here.
- **[aquasecurity/vexhub](https://github.com/aquasecurity/vexhub)** —
  the default Aqua-curated hub, populated by upstream package
  maintainers themselves. If the maintainer of the affected package
  has already authored a VEX statement, it lands here.

This hub is for SUSE Observability's **deployment-context** and
**judgment-driven** statements — assertions about how *we* deploy
the artefacts that automation can't derive: helm chart config,
network policies, non-Go runtime stacks (Java/JVM and others), and
cases that require human security review. If `govulncheck` or the
upstream maintainer can produce your statement, it belongs in their
hub, not ours.

## When to author a VEX statement

For any finding, ask:

1. **Is the vulnerable component present in the image?**
   - No -> OpenVEX `not_affected` with justification
     `component_not_present`.
2. **Is the vulnerable code reachable in our deployed runtime
   configuration?**
   - No -> OpenVEX `not_affected` with justification
     `vulnerable_code_not_in_execute_path` (or another standard
     OpenVEX justification, see the spec). Evidence required: the
     helm config, runtime flag, network policy, or analysis output
     that proves non-reachability.

If neither (1) nor (2) can be answered "no" honestly, this hub is
not the right place. Options:

- Fix the CVE (upgrade, patch, or switch artefact).
- Use `under_investigation` VEX while you triage — informational
  only, does not unblock CI gates.
- For temporary internal-CI suppression of a real CVE while waiting
  for an upstream fix, use the per-image `.trivyignore.yaml`
  mechanism in docker-images. That is operational policy, not a
  public attestation, and intentionally lives outside this hub.

## Filing a VEX statement

### Choose the lane

Default to Lane 1. Use Lane 2 only when the assertion genuinely
varies by image context — this is rare. Lane 1 is simpler,
registry-agnostic, and applies wherever Trivy finds the affected
package across our portfolio.

- **Lane 1 (default): package PURL.** Subject is the affected package
  (e.g. `pkg:maven/org.eclipse.jetty/jetty-http@9.4.57.v20241219`,
  `pkg:apk/alpine/zlib@1.2.13-r0`). One statement applies wherever
  Trivy finds the package, across every SUSE Observability image and
  every distribution registry. Use this when the assertion is true
  universally across our deployments.
- **Lane 2: OCI image PURL with package subcomponent.** Use only when
  the assertion varies per image. Subject is the OCI image PURL with
  the `repository_url` qualifier; the affected package is named in
  `subcomponents`. Because OCI PURLs are registry-coupled, author one
  VEX file per distribution registry — typically both
  `quay.io/stackstate/<image>` and the Rancher Prime
  `registry.rancher.com/suse-observability/<image>` copy. This mirrors
  Rancher's generated `rancher/vexhub` layout and lets Trivy's
  `--vex repo` lookup resolve the exact image repository.

### Steps

1. Use [vexctl](https://github.com/openvex/vexctl) to author the
   OpenVEX JSON document, written to
   `pkg/<purl-path>/scan.openvex.json` (Aqua VEX Hub layout). See
   [tools/README.md](./tools/README.md) for command examples.
   - Lane 1 path:
     `pkg/maven/org.eclipse.jetty/jetty-http/scan.openvex.json`.
   - Lane 2 paths:
     `pkg/oci/quay.io/stackstate/zookeeper/scan.openvex.json`
     and
     `pkg/oci/registry.rancher.com/suse-observability/zookeeper/scan.openvex.json`.
     Each file should contain the matching single OCI product, for
     example `pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper`.
2. Run `python3 tools/build_index.py` to regenerate `index.json`. CI
   asserts the on-disk index matches the `pkg/` tree
   (`tools/build_index.py --check`).
3. PR description must include evidence sufficient for a reviewer to
   verify the claim without re-deriving it: a config snippet,
   govulncheck output, helm values reference, network policy, or test
   output. For Lane 1, evidence must establish the assertion across
   *every* image where the package appears.
4. CODEOWNERS will route the PR to the security team and the relevant
   product team. Both approvals are required for HIGH/CRITICAL CVEs.

VEX statements typically do not expire. Annual review is recommended
for `vulnerable_code_not_in_execute_path` claims to confirm the
runtime configuration is unchanged — and especially for Lane 1
statements, since a single drift can invalidate the assertion in
multiple images at once.
