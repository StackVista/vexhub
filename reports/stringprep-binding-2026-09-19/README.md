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
