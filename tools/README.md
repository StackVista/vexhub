# vexhub tools

Two pieces of tooling, both intentionally minimal:

- **vexctl** (third-party, owned by the OpenVEX project) — authors
  OpenVEX statement files.
- **build_index.py** (this repo, stdlib only) — regenerates
  `index.json` from the contents of `pkg/`.

We deliberately do not maintain a per-statement Python script. The
authoring path goes through vexctl; the index is rebuilt from the
tree.

## Authoring statements with vexctl

Install vexctl:

```
go install github.com/openvex/vexctl@latest
# or download a release binary from https://github.com/openvex/vexctl/releases
```

Lane 1 example (package PURL — the default):

```
mkdir -p pkg/maven/org.eclipse.jetty/jetty-http
vexctl create \
  --product 'pkg:maven/org.eclipse.jetty/jetty-http@9.4.57.v20241219' \
  --vuln CVE-2026-2332 \
  --status not_affected \
  --justification vulnerable_code_not_in_execute_path \
  --author 'SUSE Observability Security Team' \
  > pkg/maven/org.eclipse.jetty/jetty-http/scan.openvex.json
```

vexctl emits a fresh `@id` (URI), `timestamp`, and OpenVEX-conforming
JSON. The `impact_statement` field can be added by editing the
resulting JSON — small file, infrequent edits.

For Lane 2 (image PURL with subcomponent), see
[vexctl docs](https://github.com/openvex/vexctl) and the OpenVEX spec.
The `--product` flag accepts an OCI PURL; subcomponents can be added
to the resulting JSON. Keep one generated file per OCI repository URL,
for example:

```
pkg/oci/quay.io/stackstate/kafka/scan.openvex.json
pkg/oci/registry.rancher.com/suse-observability/kafka/scan.openvex.json
```

The product IDs inside those files should use the matching OCI PURL,
for example `pkg:oci/kafka?repository_url=quay.io/stackstate/kafka`.

If multiple statements apply to the same package, append them to the
same file's `statements` array, or use `vexctl merge` to combine
documents.

## Regenerating index.json

After adding, modifying, or removing any `pkg/.../scan.openvex.json`
file, run:

```
python3 tools/build_index.py
```

The script walks `pkg/`, extracts product PURLs from every statement,
normalises them for VEX repository lookup, and rewrites `index.json`
from scratch — sorted, deduplicated, and matching the index shape used
by [Rancher's VEX Hub](https://github.com/rancher/vexhub). Package
versions are stripped from index IDs, while qualifiers such as OCI
`repository_url` are preserved and percent-encoded.

## CI check

Wire this into the PR pipeline so the index can't drift:

```
python3 tools/build_index.py --check
```

Exits non-zero (with a hint to run the regenerator) if the on-disk
`index.json` doesn't match what `pkg/` says it should be.

## Dependencies

- vexctl — for authoring (or hand-author the JSON; the format is
  small and stable).
- Python 3.9+ — stdlib only, no third-party packages.
