package vex_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

// Controlled finding: Trivy does not detect this embedded generic Python CVE.
// Exercise Trivy's real report -> BOM -> repository lookup -> OpenVEX filter.
func TestStringPrepBinding(t *testing.T) {
	root := os.Getenv("STRINGPREP_EVIDENCE_ROOT")
	require.NotEmpty(t, root)
	raw, err := os.ReadFile(filepath.Join(root, "published/reports/trivy.json"))
	require.NoError(t, err)
	for _, tc := range []struct {
		name, digest, arch string
		fixed              bool
	}{
		{"tag", "eda48188fa4311f85fe2f52a8badc69f5bec26a9ad292b15b9681690e33503e6", "amd64", true},
		{"index", "eda48188fa4311f85fe2f52a8badc69f5bec26a9ad292b15b9681690e33503e6", "arm64", true},
		{"amd64", "640f3b6f69949f1c958a7d89e788e5088ea9956293549182d32784a6f92f3892", "amd64", true},
		{"arm64", "cf3e4f4cf2ba6e66c6c075f68a29e0497e2465fc8672715768e755c98ac6c543", "arm64", true},
		{"unpatched", "32a25b904072a24df3c6e1d3da22e8fb7fee9e34ad98b4a73756b091acba4060", "amd64", false},
		{"unverified-rancher", "eda48188fa4311f85fe2f52a8badc69f5bec26a9ad292b15b9681690e33503e6", "amd64", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report types.Report
			require.NoError(t, json.Unmarshal(raw, &report))
			repo := "quay.io/stackstate/stackstate-k8s-agent"
			if tc.name == "unverified-rancher" {
				repo = "registry.rancher.com/suse-observability/stackstate-k8s-agent"
			}
			report.Metadata.RepoDigests = []string{repo + "@sha256:" + tc.digest}
			report.Metadata.ImageConfig.Architecture = tc.arch
			report.ArtifactName = report.Metadata.RepoDigests[0]
			if tc.name == "tag" {
				report.ArtifactName = repo + ":0812a1b8"
			}
			p, err := packageurl.FromString("pkg:generic/python@3.13.15")
			require.NoError(t, err)
			id := ftypes.PkgIdentifier{UID: "stringprep-control", PURL: &p}
			report.Results = types.Results{{Target: "controlled embedded Python finding", Class: types.ClassLangPkg, Type: ftypes.PythonPkg,
				Packages:        []ftypes.Package{{ID: "python@3.13.15", Name: "python", Version: "3.13.15", Identifier: id}},
				Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2026-17084", PkgID: "python@3.13.15", PkgName: "python", InstalledVersion: "3.13.15", PkgIdentifier: id}},
			}}
			err = vex.Filter(t.Context(), &report, vex.Options{CacheDir: filepath.Join(root, "candidate-cache"), Sources: []vex.Source{{Type: vex.TypeRepository}}})
			require.NoError(t, err)
			if tc.fixed {
				require.Empty(t, report.Results[0].Vulnerabilities)
				require.Len(t, report.Results[0].ModifiedFindings, 1)
				require.Equal(t, types.FindingStatusFixed, report.Results[0].ModifiedFindings[0].Status)
			} else {
				require.Len(t, report.Results[0].Vulnerabilities, 1)
				require.Empty(t, report.Results[0].ModifiedFindings)
			}
			// Same controlled finding must remain active with merged source-only VEX43.
			baseline := report
			baseline.Results = types.Results{{Target: "controlled embedded Python finding", Class: types.ClassLangPkg, Type: ftypes.PythonPkg,
				Packages:        []ftypes.Package{{ID: "python@3.13.15", Name: "python", Version: "3.13.15", Identifier: id}},
				Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2026-17084", PkgID: "python@3.13.15", PkgName: "python", InstalledVersion: "3.13.15", PkgIdentifier: id}},
			}}
			err = vex.Filter(t.Context(), &baseline, vex.Options{CacheDir: filepath.Join(root, "baseline-cache"), Sources: []vex.Source{{Type: vex.TypeRepository}}})
			require.NoError(t, err)
			require.Len(t, baseline.Results[0].Vulnerabilities, 1)
			require.Empty(t, baseline.Results[0].ModifiedFindings)
			b, err := json.MarshalIndent(report, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(root, "scans", tc.name+"-trivy-controlled.json"), b, 0644))
		})
	}
}
