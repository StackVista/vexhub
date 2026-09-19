# StringPrep verified Quay image binding — candidate evidence

This candidate extends only VEX43's existing CVE-2026-17084 `fixed` assertion.
All 32 other statements in the agent document are unchanged as parsed JSON.
No Python source, applicability decision, exception, scanner gate, or Go hold changes.

## Artifact identity and existing runtime review

- [Merged VEX43](https://github.com/StackVista/vexhub/pull/43).
- [Agent publication 35352622819](https://github.com/StackVista/stackstate-agent/actions/runs/35352622819).
- [Canonical scan 35425413598, attempt 1](https://github.com/StackVista/cve-reporter/actions/runs/35425413598), agent artifact `10578747940`.
- [Independent packaged-runtime review](https://omnigent.tooling.stackstate.io/c/4e86b69500ba5480b97e48f0b49385c8): upstream backport, installed StringPrep hash and four IDNA regressions plus ASCII control passed on AMD64 native and ARM64 QEMU. Reused; no further Python source work.
- [Prior audit and handoff](https://github.com/StackVista/stackstate-mission-control/blob/main/official-plans/stackstate-agent-python-vex-audit-2026-09-18.md).

Live `skopeo inspect --raw` of `quay.io/stackstate/stackstate-k8s-agent:0812a1b8`
returned [quay-index.json](quay-index.json), whose SHA256 is the index digest below.
Both child image configurations name merge commit
`0812a1b82c80f28667fcdb646d2d0478384c9bee` and publication35352622819.
The merge and reviewed commit `9f51215785bbf3c400065aeb3e3eb8c94e7f18ec`
have the same Git tree `226e90bf2c7a699613b90b4cad94ae54ca601e6e`.
Selected configuration fields and canonical scan metadata are in [identity.json](identity.json).

| Product | SHA256 |
| --- | --- |
| Index | `eda48188fa4311f85fe2f52a8badc69f5bec26a9ad292b15b9681690e33503e6` |
| AMD64 | `640f3b6f69949f1c958a7d89e788e5088ea9956293549182d32784a6f92f3892` |
| ARM64 | `cf3e4f4cf2ba6e66c6c075f68a29e0497e2465fc8672715768e755c98ac6c543` |
| Unpatched control, tag `13451dce` | `32a25b904072a24df3c6e1d3da22e8fb7fee9e34ad98b4a73756b091acba4060` |

The unpatched control index was also checked live. Its failing IDNA regressions
are recorded in the prior audit; it also reports Python3.13.15.

## Identifier choice

Six OCI products bind three immutable digests with two scanner-specific qualifier
forms. Grype0.118.0 constructs `repository_url=quay.io/stackstate`; Trivy0.74.0
constructs `repository_url=quay.io/stackstate/stackstate-k8s-agent`.
The index is regenerated to cover the added namespace-form lookup. Every product
retains `pkg:generic/python@3.13.15` as a subcomponent. Tag scanning must resolve
the verified digest; there is no tag-only, unversioned or Rancher fixed product.
A different digest will not inherit the assertion even if it uses the same tag.

Primary implementations: [Grype digest identifiers](https://github.com/anchore/grype/blob/v0.118.0/grype/vex/openvex/implementation.go),
[Trivy OCI PURL construction](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/purl/purl.go),
[Trivy fixed-status filtering](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/vex/openvex.go).

## Review and publication boundary

Candidate only. Independent review and explicit human VEX/merge approval remain
required before publication. After approved merge, verify the downloaded published
hub with both consumers; Rancher migration and parity remain a separate follow-up
and require verified Rancher identities. Agent511 and Go holds remain intact.
This is not whole-image clearance. Tracking: [vexhub34](https://github.com/StackVista/vexhub/issues/34)
and [cve-reporter29](https://github.com/StackVista/cve-reporter/issues/29); the supervisor owns ticket updates.

## Trivy consumption control

Native Trivy0.74.0 tag, index and unpatched-image scans completed using the shared
`scan-image` flags and candidate repository cache. They contain no StringPrep
finding; that absence is **not** fixed-assertion consumption evidence.

The [controlled test](stringprep_binding_test.go) extends Trivy's existing
`pkg/vex` test harness at v0.74.0, commit
`e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994`. It reads the canonical scan's
Trivy report, supplies a controlled `CVE-2026-17084` finding with
`pkg:generic/python@3.13.15`, and runs Trivy's actual report-to-BOM,
repository-index lookup and OpenVEX filter. Only controlled identity/finding
fields are changed; no scanner matching implementation is copied or replaced.

[Output](trivy-controlled.log) and [selected exact result records](trivy-results.json):

| Identity | Candidate result | Merged source-only baseline |
| --- | --- | --- |
| Tag `0812a1b8`, resolved index, AMD64 | `fixed`, source `VEX Repository: stackvista` | active |
| Index digest, ARM64 | `fixed` | active |
| AMD64 child digest | `fixed` | active |
| ARM64 child digest | `fixed` | active |
| Unpatched `13451dce` index, same Python version | active | active |
| Unverified Rancher repository, even with candidate digest | active | active |

These are controlled filter results, not native vulnerability detections or
verification of any Rancher image. Candidate files were overlaid in a private
cache under the existing StackVista repository name; its source label does not
mean this candidate has been published to the main hub.

## Reproduction

Use a private build environment. Shared inputs come from
[image-pipeline at 27cf07bd5f5f3bafdb714e3b24d72d85480d2a60](https://github.com/StackVista/image-pipeline/tree/27cf07bd5f5f3bafdb714e3b24d72d85480d2a60):
`.github/actions/scan-image/action.yml` and `vex/repository.yaml`.
Versions match that action: Grype0.118.0 and Trivy0.74.0.

1. Download both hubs with the shared `vex/repository.yaml` installed at
   `~/.trivy/vex/repository.yaml`, then `trivy vex repo download`.
2. Set `STRINGPREP_EVIDENCE_ROOT` to an absolute scratch directory. Copy
   `~/.cache/trivy/vex` into both `$STRINGPREP_EVIDENCE_ROOT/baseline-cache/`
   and `$STRINGPREP_EVIDENCE_ROOT/candidate-cache/`. Baseline here was
   vexhub main `73cde8403263eb091ebaa5b57651ee81a4967750` (merged VEX43).
3. In candidate-cache only, replace
   `vex/repositories/stackvista/0.1/pkg/oci/stackstate-k8s-agent/scan.openvex.json`
   and `vex/repositories/stackvista/0.1/index.json` with this PR's files.
   Keep the descriptor and all other downloaded documents unchanged.
4. Collect Grype documents with the shared action's validation step below.
   An initial local invocation omitted its JSON filter and rejected a Rancher
   Git LFS pointer; corrected runs use the shared predicate, skipping that
   non-JSON file exactly as the action does. This is not a VEX or scanner change.
5. Scan the tag, index, child digests and unpatched control with the same DB.
   Repeat the tag against baseline-cache. No exception files or severity gates
   are relaxed; these targeted scanner runs inspect disposition rather than
   claiming a clean whole-image gate.

```bash
vex_cache="$STRINGPREP_EVIDENCE_ROOT/candidate-cache/vex/repositories"
vex_args=()
while IFS= read -r doc; do
  if jq -e 'type == "object" and (.statements | type == "array")' "$doc" >/dev/null 2>&1; then
    vex_args+=(--vex "$doc")
  fi
done < <(find "$vex_cache" -type f -iname '*openvex*.json' | sort)
# Set image to each reference in the identity table; use linux/arm64 for ARM64.
GRYPE_DB_AUTO_UPDATE=false grype "$image" "${vex_args[@]}" \
  --by-cve --platform linux/amd64 -o json=grype.json
trivy image "$image" --scanners vuln --format json --output trivy.json \
  --vex repo --skip-vex-repo-update --show-suppressed --exit-code 0 \
  --cache-dir "$STRINGPREP_EVIDENCE_ROOT/candidate-cache"
```

For the controlled Trivy test, download the existing canonical report rather than
inventing image metadata, and run the supplied test in the upstream harness:

```bash
mkdir -p "$STRINGPREP_EVIDENCE_ROOT/published" "$STRINGPREP_EVIDENCE_ROOT/scans"
gh run download 35425413598 -R StackVista/cve-reporter \
  -n chart-scan-quay.io-stackstate-stackstate-k8s-agent-0812a1b8-9673b40c2081 \
  -D "$STRINGPREP_EVIDENCE_ROOT/published"
# In a Trivy checkout at e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994:
# copy this report directory's stringprep_binding_test.go into pkg/vex/.
go test ./pkg/vex -run '^TestStringPrepBinding$' -count=1 -v
```

The fixture is an audit artifact, not a new maintained scanner or production
workflow. Native Trivy scanning still reports no StringPrep finding. The fixture
makes that limitation explicit and verifies the actual consumer's behavior if
the finding is present.

## Grype native scanner results

[Exact StringPrep records, image metadata, DB identity and report hashes](grype-results.json).
All six runs use Grype0.118.0 and the same DB built `2026-09-19T06:27:50Z`,
archive checksum `sha256:28831b25b36ed42597025728d24d61a7e3a9bbf198ed38c1c7211678807e4455`.
Both caches supply 1,221 valid OpenVEX documents through the shared JSON predicate.
The candidate changes only the agent document and generated index.

| Native input | VEX | StringPrep | All active / ignored |
| --- | --- | --- | --- |
| `0812a1b8` tag, AMD64 | source-only baseline | active | 2 / 12 |
| `0812a1b8` tag, AMD64 | candidate | `fixed` | 1 / 13 |
| Verified index digest, AMD64 | candidate | `fixed` | 1 / 13 |
| Verified AMD64 digest | candidate | `fixed` | 1 / 13 |
| Verified ARM64 digest | candidate | `fixed` | 1 / 13 |
| Unpatched `13451dce`, AMD64 | candidate | active | 2 / 12 |

Each positive result contains the actual StringPrep match in `ignoredMatches`
with `appliedIgnoreRules: [{"namespace":"vex","vex-status":"fixed"}]`.
The negative control still contains the CVE in `matches`. Comparison by CVE,
package and version proves all other dispositions equal the baseline, including
both architecture results. The remaining active Python finding, CVE-2026-82049, is left untouched.
The canonical scan used an older DB; it is reused for provenance, while the
candidate/baseline causal comparison above uses one identical current DB.

Local index validation, `git diff --check`, signed-commit verification, and
preservation of all 32 other agent statements pass. PR CI runs the existing
required index check; no checks were removed or weakened.
