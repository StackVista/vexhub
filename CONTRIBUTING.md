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
3. Add an **evidence report** at
   `reports/evidence/<scope>-vex-evidence-<YYYY-MM-DD>.md`. It must
   include the chart values, runtime command, container ports, and
   the per-CVE reasoning that justifies each `not_affected` claim.
   For Lane 1, evidence must establish the assertion across *every*
   image where the package appears. The PR description should link
   to the report rather than duplicate it.
4. CODEOWNERS will route the PR to the security team and the relevant
   product team. For HIGH/CRITICAL CVEs in `pkg/oci/...`, an
   independent **security review** is required (see below) before the
   security-team approval is granted.

### Security review (required for HIGH/CRITICAL OCI VEX)

A separate person from the VEX author opens a follow-up MR stacked
on the VEX MR that:

1. Adds a security review report at
   `reports/security-reviews/<scope>-vex-security-review-<YYYY-MM-DD>.md`.
   The report frames each statement adversarially — for each CVE,
   state what would have to be true to falsify the claim, then check
   whether the supported deployment satisfies those conditions, citing
   primary sources (the upstream advisory's named class/method, chart
   template line numbers, default `values.yaml` lines).
2. Applies any justification or impact-statement corrections found
   during review by **regenerating the affected `scan.openvex.json`
   files with `vexctl`** (not by hand-editing JSON). Use
   `SOURCE_DATE_EPOCH` so timestamps are deterministic.
3. Verifies the regenerated files still suppress the same findings
   in Trivy:

   ```bash
   trivy image --quiet --skip-db-update --scanners vuln --severity HIGH \
     --vex pkg/oci/<registry>/<namespace>/<image>/scan.openvex.json \
     --show-suppressed \
     <registry>/<namespace>/<image>:<tag>
   ```

   Paste the suppressed-vulnerabilities table into the security
   review report so reviewers can confirm parity vs. the original
   VEX MR.
4. Re-runs `python3 tools/build_index.py --check` to confirm the
   index is still in sync.

The security review is not an approval rubber-stamp; if the reviewer
cannot construct an exploit path through the supported deployment,
that's a UPHELD verdict and the report records the falsification
attempts that were made. If the reviewer *can* construct one, the
VEX MR must change status from `not_affected` to something accurate
(or be withdrawn) before merging.

### Authoring and regenerating with vexctl

OpenVEX files are generated by `vexctl create` plus `vexctl add`,
not by hand-editing JSON. To make regeneration deterministic across
authors and reviewers, set `SOURCE_DATE_EPOCH` to a fixed UTC
timestamp before running vexctl — both the document `timestamp` /
`last_updated` and per-statement timestamps will be pinned to it.

```bash
export SOURCE_DATE_EPOCH=$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' \
  '2026-05-08T08:00:00Z' '+%s')   # macOS
# Linux: export SOURCE_DATE_EPOCH=$(date -u -d '2026-05-08T08:00:00Z' '+%s')
```

When a security review changes a justification or rewrites an impact
statement, regenerate the entire `scan.openvex.json` file from
scratch (one `vexctl create` followed by N-1 `vexctl add -i`
invocations). Do not edit the JSON in place — it bypasses the
canonicalisation and version-bump logic vexctl maintains. See
[tools/README.md](./tools/README.md) for command shapes.

### Lifecycle

VEX statements typically do not expire. Annual review is recommended
for `vulnerable_code_not_in_execute_path` claims to confirm the
runtime configuration is unchanged — and especially for Lane 1
statements, since a single drift can invalidate the assertion in
multiple images at once. An annual review is documented as a
follow-up security review report under
`reports/security-reviews/`.
