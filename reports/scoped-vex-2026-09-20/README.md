# Scoped process-agent, backup and Python VEX candidate

Human VEX decisions remain required. This proposal changes no exception, delivery
permission or production artifact. Existing StringPrep bindings and other
applicability statements remain unchanged.

| Product | Proposed change | Existing evidence |
| --- | --- | --- |
| Process-agent | Remove only x/crypto `@v0.53.0` from the four existing GO-2026-5932 subcomponents; retain product scope and `not_affected` / `vulnerable_code_not_present` | [Canonical #27](https://github.com/StackVista/cve-reporter/issues/27), including September 8/9 version-matching controls and the Security Team assessment |
| Backup CLI | Separate `not_affected` / `vulnerable_code_not_present` for five accepted v0.10.0 archive SHA256 identities and x/crypto v0.56.0 | [Canonical #57](https://github.com/StackVista/cve-reporter/issues/57), [all-platform independent review](https://omnigent.tooling.stackstate.io/c/828da530563e5baca8d2c3a4ab6f6fbe) |
| Agent Python | `fixed` for CVE-2026-82049 at exact PR532 source `98c358700422951715f0473ba345a664f3a5c2db`; no image products | [PR532](https://github.com/StackVista/stackstate-agent/pull/532), [accepted independent source review](https://omnigent.tooling.stackstate.io/c/4e86b69500ba5480b97e48f0b49385c8), [native package/image CI](https://github.com/StackVista/stackstate-agent/actions/runs/35460384237) |

Process-agent's reviewed guard is still in
[`scripts/verify-openpgp-absent.sh`](https://github.com/StackVista/stackstate-process-agent/blob/fe7d17e97be17d62ac0ae1cf0760826cc6303f43/scripts/verify-openpgp-absent.sh),
called by `rake ci` with release/BPF tags. It rejects future OpenPGP imports.
[PR290](https://github.com/StackVista/stackstate-process-agent/pull/290) delivery
permission remains separate from the VEX decision. Its UNKNOWN GO-2026-5932 and
expired September 10 exception remain disclosed. Approval must be followed by
exact-statement consumption without local exceptions before retiring an exception.

Backup's five binaries are commit `5feee112a425fcdf3bf92e15b5809cf61f68d612`,
Go1.26.6 and x/crypto0.56.0. The reviewer checked source, symbols and all five
binaries: no affected OpenPGP package/call, while SBOM scans retain UNKNOWN
GO-2026-5932. The five archive hashes in the new document match that review and
live [GitHub release metadata](https://github.com/StackVista/stackstate-backup-cli/releases/tag/v0.10.0).
These are **archive hashes, not OCI digests**. No other product inherits the
process-agent assessment; backup has its own evidence and decision.

Python stays 3.13.15. The accepted upstream backport and both packaged interpreters
have `tarfile.py` SHA256 `7ad04a66bb92373bd6d2552a2f01fce8a4ca95463ebf661612fd574465977929`.
The source URL follows VEX43's source-only convention. It cannot clear a shipped
image. After actual merge/publication, verify image identities and packaged patch,
then propose digest bindings separately. Tracking: [cve-reporter#29](https://github.com/StackVista/cve-reporter/issues/29)
and [vexhub#34](https://github.com/StackVista/vexhub/issues/34).

## Matching validation

The supplied [controlled test](scoped_candidate_test.go) uses the real OpenVEX
matcher at go-vex **v0.2.8** (Grype0.118.0 dependency) and **v0.2.7**
(Trivy0.74.0 dependency). Both pass. These are identifier/disposition controls,
**not native scanner runs or proof that unpublished VEX has been consumed**.
Existing scanner, package and source reviews above are reused; no rebuild or broad
scan was repeated. No raw evidence dump or new production scanner is introduced.

| Control | Result on both library versions |
| --- | --- |
| Process-agent v0.56.0 with merged baseline | No GO-2026-5932 match |
| Candidate process-agent, all four existing products, x/crypto0.53/0.56 and synthetic0.57 | `not_affected` |
| Unrelated image names with same module | No match |
| Each accepted backup archive identity and x/crypto0.56 | `not_affected` |
| Unrelated artifact name, changed/missing archive hash, changed module version, generic module-only product | No match |
| Shared `pkg:oci/cve-release-artifact`, including a backup tag | No match |
| Exact PR532 source and Python3.13.15 | `fixed` |
| Unpatched source, published unpatched index, bare image or generic Python3.13.15 | No CVE-2026-82049 match |

To reproduce, check out upstream `openvex/go-vex` at each version, copy the supplied
test into `pkg/vex/`, then run:

```sh
VEXHUB_ROOT=/absolute/path/to/this/pr go test ./pkg/vex -run '^TestScopedCandidate$' -count=1 -v
```

The repository must contain baseline commit `c5d9faa717595baba6c8bd924249bccf233325e1`.
Index validation and parsed-JSON checks also confirm preservation of every old
agent statement, the three process-agent containerd statements and all four
existing process-agent product identifiers.

## Concrete supervisor handoff: backup scan identity

Assign the narrow identity repair under [#62](https://github.com/StackVista/cve-reporter/issues/62),
with the coverage obligation under [#68](https://github.com/StackVista/cve-reporter/issues/68):

1. At reporter source `de6e601c4722b85675f58f120b0a331dc15dc1e6`,
   `app/chart_scan_matrix.py` assigns every release asset `cve-release-artifact:<url-slug>`;
   `.github/workflows/chart-scan.yml` imports the verified rootfs under that name.
   Preserve original asset URL, owner and finding/revision keys. Do not broaden VEX
   to this shared product or repurpose an archive hash as an OCI manifest digest.
2. After checksum verification, carry the exact archive identity
   `pkg:generic/stackstate-backup-cli-release-archive@sha256:<verified archive hash>`
   into the root component seen by **both** VEX consumers, retaining the x/crypto
   subcomponent. Prefer supported SBOM/root metadata in the shared scan path;
   a Grype-only name override does not establish Trivy parity. This PR does not
   claim that current synthetic images expose that identity.
3. Demonstrate candidate/baseline consumption with all five accepted archives and
   an unrelated release asset containing the same x/crypto finding. Changed hash,
   missing checksum and owner mismatch must not inherit the decision. Preserve
   UNKNOWN when no applicable approved statement matches; no local exceptions.
4. Keep Unix results unassessed where native Grype matching is absent. Reuse the
   accepted all-platform SBOM evidence and verify supported SBOM scanning preserves
   package coverage; empty Unix detections must not become a clean claim.

Until this repair and human approval, the backup proposal intentionally remains
inert in the central scan. No new backup release is needed. Supervisor owns ticket
coordination; independent VEX review and each product's human disposition remain.
