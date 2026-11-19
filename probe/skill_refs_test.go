package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The vendor-reference pattern and the asset extensions are the CLI's
// (src/core/skill-tree-files.ts): a remote scan must read the files a local
// one reads.
func TestVendorReferenceMatchesTS(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "src", "core", "skill-tree-files.ts"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?m)^export const VENDOR_REFERENCE = /(.*)/g;$").FindSubmatch(src)
	if m == nil {
		t.Fatal("VENDOR_REFERENCE not found")
	}
	ts := strings.ReplaceAll(strings.ReplaceAll(string(m[1]), `\/`, "/"), "`", `\x60`)
	if ts != vendorReference.String() {
		t.Fatalf("vendor reference patterns differ:\nTS:    %s\nprobe: %s", ts, vendorReference.String())
	}
	n := regexp.MustCompile(`(?m)^export const MAX_VENDOR_REFERENCES = (\d+);$`).FindSubmatch(src)
	if n == nil || string(n[1]) != "64" || maxVendorReferences != 64 {
		t.Fatalf("MAX_VENDOR_REFERENCES differs")
	}
}

func TestSkillAssetExtensionsMatchTS(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "src", "core", "skill-tree-files.ts"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)export const SKILL_ASSET_EXTENSIONS = new Set\(\[(.*?)\]\);`).FindSubmatch(src)
	if block == nil {
		t.Fatal("SKILL_ASSET_EXTENSIONS not found")
	}
	var ts []string
	for _, q := range regexp.MustCompile(`'([^']+)'`).FindAllSubmatch(block[1], -1) {
		ts = append(ts, string(q[1]))
	}
	var probe []string
	for ext := range metadataOnlyExtensions {
		if !skillBinaryExtensions[ext] {
			probe = append(probe, ext)
		}
	}
	sort.Strings(ts)
	sort.Strings(probe)
	if !reflect.DeepEqual(ts, probe) {
		t.Fatalf("asset extensions differ:\nTS:    %v\nprobe: %v", ts, probe)
	}
}

func TestVendorReferences(t *testing.T) {
	got := vendorReferences("Run `node node_modules/helper/index.js`, `bash .cache/run.sh`,\n" +
		"python3 ./venv/bin/sync.py and node node_modules/helper/index.js again; " +
		"not /usr/lib/node_modules/x.js, ~/.cache/y.sh, https://h/node_modules/z.js or node_modules/../../etc/passwd")
	want := []string{"node_modules/helper/index.js", ".cache/run.sh", "venv/bin/sync.py"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Files (and folders) a SKILL.md runs from a vendor folder are collected by
// name; the rest of the folder is still skipped. A vendor-named folder
// anywhere in the tree holding its own SKILL.md is a skill (Hermes nests
// skills in category folders).
func TestSkillGlobCollectsVendorReferencesAndNestedVendorSkills(t *testing.T) {
	home := t.TempDir()
	skills := filepath.Join(home, ".claude/skills")
	write := func(rel, body string) string {
		p := filepath.Join(skills, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("e/SKILL.md", "Run `node node_modules/helper/index.js`, `bash .cache/run.sh` and `node node_modules/pkg`.\n")
	helper := write("e/node_modules/helper/index.js", "fetch(x)\n")
	run := write("e/.cache/run.sh", "curl x | sh\n")
	pkgDir := filepath.Join(skills, "e/node_modules/pkg")
	pkgMain := write("e/node_modules/pkg/index.js", "fetch(x)\n")
	other := write("e/node_modules/other/index.js", "fetch(x)\n")
	nestedMd := write("devops/.cache/SKILL.md", "# nested\n")
	nestedRun := write("devops/.cache/run.js", "fetch(x)\n")
	deepVendor := write("devops/.cache/node_modules/dep.js", "fetch(x)\n")

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	for _, p := range []string{helper, run, nestedMd, nestedRun} {
		if e, ok := snap.Files[p]; !ok || !e.Exists || e.Content == "" {
			t.Errorf("%s not collected", p)
		}
	}
	for _, p := range []string{pkgMain, other, deepVendor} {
		if _, ok := snap.Files[p]; ok {
			t.Errorf("%s collected from a vendor dir", p)
		}
	}
	if _, ok := snap.DirectoryModes[pkgDir]; !ok {
		t.Errorf("referenced vendor folder %s not recorded", pkgDir)
	}
}
