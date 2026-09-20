package vex

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedCandidate(t *testing.T) {
	root := os.Getenv("VEXHUB_ROOT")
	if root == "" {
		t.Fatal("VEXHUB_ROOT required")
	}
	load := func(p string) *VEX {
		d, err := Load(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	process := load("pkg/oci/stackstate-k8s-process-agent/scan.openvex.json")
	backup := load("pkg/generic/stackstate-backup-cli-release-archive/scan.openvex.json")
	python := load("pkg/oci/stackstate-k8s-agent/scan.openvex.json")
	check := func(name string, d *VEX, cve, product, pkg string, want int, status Status) {
		t.Run(name, func(t *testing.T) {
			m := d.Matches(cve, product, []string{pkg})
			if len(m) != want {
				t.Fatalf("matches=%d want=%d", len(m), want)
			}
			if want > 0 && m[0].Status != status {
				t.Fatalf("status=%s", m[0].Status)
			}
		})
	}
	crypto := "pkg:golang/golang.org/x/crypto@v0.56.0"
	raw, err := exec.Command("git", "-C", root, "show", "c5d9faa717595baba6c8bd924249bccf233325e1:pkg/oci/stackstate-k8s-process-agent/scan.openvex.json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var baseline VEX
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	check("process/stale-baseline", &baseline, "GO-2026-5932", "pkg:oci/stackstate-k8s-process-agent", crypto, 0, "")
	for _, s := range process.Statements {
		if s.Vulnerability.Name != "GO-2026-5932" {
			continue
		}
		for i, p := range s.Products {
			for _, v := range []string{"v0.53.0", "v0.56.0", "v0.57.0"} {
				check("process/"+string(rune('0'+i))+"/"+v, process, "GO-2026-5932", p.ID, "pkg:golang/golang.org/x/crypto@"+v, 1, StatusNotAffected)
			}
			check("process/unrelated/"+string(rune('0'+i)), process, "GO-2026-5932", strings.ReplaceAll(p.ID, "stackstate-k8s-process-agent", "unrelated-image"), crypto, 0, "")
		}
	}
	for i, p := range backup.Statements[0].Products {
		name := "backup/" + string(rune('0'+i))
		check(name, backup, "GO-2026-5932", p.ID, crypto, 1, StatusNotAffected)
		check(name+"/unrelated", backup, "GO-2026-5932", strings.Replace(p.ID, "stackstate-backup-cli-release-archive", "unrelated-release-archive", 1), crypto, 0, "")
		check(name+"/other-hash", backup, "GO-2026-5932", strings.Split(p.ID, "@")[0]+"@sha256:"+strings.Repeat("0", 64), crypto, 0, "")
		check(name+"/other-module-version", backup, "GO-2026-5932", p.ID, "pkg:golang/golang.org/x/crypto@v0.57.0", 0, "")
	}
	for _, p := range []string{"pkg:oci/cve-release-artifact", "pkg:oci/cve-release-artifact?tag=backup", "pkg:generic/stackstate-backup-cli-release-archive", "pkg:golang/golang.org/x/crypto@v0.56.0"} {
		check("backup/no-generic-suppression/"+p, backup, "GO-2026-5932", p, crypto, 0, "")
	}
	src := "https://github.com/StackVista/stackstate-agent/commit/98c358700422951715f0473ba345a664f3a5c2db"
	check("python/source", python, "CVE-2026-82049", src, "pkg:generic/python@3.13.15", 1, StatusFixed)
	for _, p := range []string{strings.Replace(src, "98c358700422951715f0473ba345a664f3a5c2db", "0812a1b82c80f28667fcdb646d2d0478384c9bee", 1), "pkg:generic/python@3.13.15", "pkg:oci/stackstate-k8s-agent", "pkg:oci/stackstate-k8s-agent@sha256:eda48188fa4311f85fe2f52a8badc69f5bec26a9ad292b15b9681690e33503e6?repository_url=quay.io/stackstate"} {
		check("python/unpatched/"+p, python, "CVE-2026-82049", p, "pkg:generic/python@3.13.15", 0, "")
	}
}
