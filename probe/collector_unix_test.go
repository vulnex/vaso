//go:build unix

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A command that exits but leaves a background child holding stdout must not
// hold the probe until that child ends, and a timeout kills its whole group.
func TestRunCommandBoundedByBackgroundChildrenAndTimeout(t *testing.T) {
	commandAllowlist["sh"] = true
	defer delete(commandAllowlist, "sh")
	alive := func(pid string) bool {
		n, err := strconv.Atoi(strings.TrimSpace(pid))
		if err != nil {
			t.Fatalf("no pid in %q", pid)
		}
		for i := 0; i < 20; i++ {
			if syscall.Kill(n, 0) != nil {
				return false
			}
			time.Sleep(50 * time.Millisecond)
		}
		return true
	}

	start := time.Now()
	out := runCommand(CommandRequest{ID: "t", Cmd: "sh", Args: []string{"-c", "sleep 30 & echo $!; echo tool 1.2.3"}, Timeout: 5000}, "")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("waited %v for a background child", time.Since(start))
	}
	lines := strings.Split(out.Stdout, "\n")
	if out.ExitCode != 0 || len(lines) < 2 || lines[1] != "tool 1.2.3" {
		t.Fatalf("output lost: %+v", out)
	}
	if alive(lines[0]) {
		t.Fatal("background child left running")
	}

	start = time.Now()
	out = runCommand(CommandRequest{ID: "t", Cmd: "sh", Args: []string{"-c", "sleep 30 & echo $!; wait"}, Timeout: 300}, "")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v", time.Since(start))
	}
	if out.ExitCode == 0 || alive(strings.Split(out.Stdout, "\n")[0]) {
		t.Fatalf("timed-out group not killed: %+v", out)
	}
}

func TestCollectFileSkipsFIFOsAndDevices(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.js")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	zero := filepath.Join(dir, "zero.js")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	c := &collector{budget: 1 << 20}
	done := make(chan [2]FileEntry, 1)
	go func() { done <- [2]FileEntry{c.collectFile(fifo, false), c.collectFile(zero, false)} }()
	select {
	case got := <-done:
		for i, e := range got {
			if !e.Exists || !e.ContentOmitted || e.Content != "" {
				t.Fatalf("entry %d: want exists + content omitted, got %+v", i, e)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collectFile blocked on a FIFO or /dev/zero")
	}
}

func TestGlobFollowsSkillLinksOutsideTheTree(t *testing.T) {
	base := t.TempDir()
	base, _ = filepath.EvalSymlinks(base)
	skills := filepath.Join(base, "skills")
	checkout := filepath.Join(base, "checkout", "linked")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(skills, "local"), 0o755))
	must(os.MkdirAll(filepath.Join(checkout, "lib"), 0o755))
	must(os.WriteFile(filepath.Join(skills, "local", "index.js"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(checkout, "index.js"), []byte("eval(x)"), 0o644))
	must(os.WriteFile(filepath.Join(checkout, "lib", "util.js"), []byte("y"), 0o644))
	must(os.Symlink(checkout, filepath.Join(skills, "linked")))
	must(os.Symlink(filepath.Join(skills, "local"), filepath.Join(skills, "alias")))        // into the tree
	must(os.Symlink(filepath.Join(base, "checkout"), filepath.Join(checkout, "lib", "up"))) // back up: cycle

	snap := Collect(ProbeManifest{GlobPatterns: []string{skills + "/**"}}, false)

	linked := filepath.Join(skills, "linked", "lib", "util.js")
	if e, ok := snap.Files[linked]; !ok || e.Content != "y" {
		t.Fatalf("file behind an outside link not collected under the link path: %+v", e)
	}
	if _, ok := snap.Files[filepath.Join(skills, "alias", "index.js")]; ok {
		t.Fatal("a link back into the tree was walked twice")
	}
	for p := range snap.Files {
		if strings.Contains(p, "/up/") {
			t.Fatalf("followed a link to a parent of a walked tree: %s", p)
		}
	}
	if snap.Symlinks[filepath.Join(skills, "linked")] != checkout {
		t.Fatalf("link target not recorded: %v", snap.Symlinks)
	}
}

func TestRootResolvesSystemBinariesBeforeUserDirs(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// A planted `which` in a user's bin dir
	if err := os.WriteFile(filepath.Join(bin, "which"), []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	homes := []UserHome{{Username: "eve", Path: home}}

	orig := runningAsRoot
	defer func() { runningAsRoot = orig }()

	runningAsRoot = func() bool { return false }
	if got := resolveBinary("which", buildAugmentedPath(homes, "/usr/bin:/bin")); got != filepath.Join(bin, "which") {
		t.Fatalf("non-root: user dir first, got %s", got)
	}
	runningAsRoot = func() bool { return true }
	path := buildAugmentedPath(homes, "/usr/bin:/bin")
	if got := resolveBinary("which", path); got != "/usr/bin/which" {
		t.Fatalf("root: system which must win, got %s", got)
	}
	// Commands run as root get a PATH without user-writable dirs
	for _, d := range filepath.SplitList(rootChildPath(path)) {
		if strings.HasPrefix(d, home) {
			t.Fatalf("root child PATH contains a user dir: %s", d)
		}
	}
	if rootSafe(filepath.Join(bin, "which")) {
		t.Fatal("a user-owned binary is not root-safe")
	}
	if !rootSafe("/bin/sh") {
		t.Fatal("/bin/sh should be root-safe")
	}
}

func TestUnlistableDirectoryStillRecorded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	profile := filepath.Join(root, "Comet")
	if err := os.Mkdir(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profile, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(profile, 0o755)

	snap := Collect(ProbeManifest{DirectoryListings: []string{profile}}, false)
	if _, listed := snap.Directories[profile]; listed {
		t.Fatal("an unreadable directory has no listing")
	}
	if mode, ok := snap.DirectoryModes[profile]; !ok || mode != 0 {
		t.Fatalf("unreadable directory not recorded as present: %v", snap.DirectoryModes)
	}

	// A config behind it is denied, and the directory that denied it is recorded
	cfg := filepath.Join(profile, "config.json")
	snap = Collect(ProbeManifest{FilePaths: []string{cfg}}, false)
	if e := snap.Files[cfg]; !e.Denied || e.Exists {
		t.Fatalf("config behind a mode-000 directory: %+v", e)
	}
	if mode, ok := snap.DirectoryModes[profile]; !ok || mode != 0 {
		t.Fatalf("denying directory not recorded: %v", snap.DirectoryModes)
	}
}

func TestUnlistableSkillDirKeepsSkillMd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "helper")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# helper"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(skill, 0o111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(skill, 0o755)

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(root, "skills") + "/**"}}, false)
	if e := snap.Files[filepath.Join(skill, "SKILL.md")]; !e.Exists || e.Content != "# helper" {
		t.Fatalf("SKILL.md of an unlistable skill dir not collected: %+v", e)
	}
	if snap.DirectoryModes[skill] != 0o111 {
		t.Fatalf("mode of the unlistable skill dir not recorded: %v", snap.DirectoryModes)
	}
}

func TestUnlistableSkillDirCollectsKnownNames(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "evil")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"SKILL.md", "package.json"} {
		if err := os.WriteFile(filepath.Join(skill, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(skill, 0o111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(skill, 0o755)

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(root, "skills") + "/**"}}, false)
	for _, n := range []string{"SKILL.md", "package.json"} {
		if e := snap.Files[filepath.Join(skill, n)]; !e.Exists {
			t.Fatalf("%s in an unlistable skill dir not collected by name: %+v", n, e)
		}
	}
}

func TestDropCredentialUsesOwnersPrimaryGroup(t *testing.T) {
	f := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	owner, fileGid, _ := fileOwner(info)
	if owner == 0 {
		t.Skip("needs a non-root file owner")
	}
	saved := primaryGid
	defer func() { primaryGid = saved }()
	primaryGid = func(uid int) (int, bool) { return 4242, uid == owner }

	uid, gid, userOwned, refuse := dropCredential(info)
	if refuse != "" || !userOwned || uid != owner || gid != 4242 || gid == fileGid {
		t.Fatalf("got uid=%d gid=%d userOwned=%v refuse=%q (file gid %d)", uid, gid, userOwned, refuse, fileGid)
	}

	primaryGid = func(int) (int, bool) { return 0, false }
	if _, _, _, refuse := dropCredential(info); refuse == "" {
		t.Fatal("an owner without an account must be refused")
	}
}

func TestPrimaryGidResolvesTheCurrentUser(t *testing.T) {
	g, ok := primaryGid(os.Getuid())
	if !ok || g != os.Getgid() {
		t.Fatalf("primaryGid(%d) = %d,%v; want %d", os.Getuid(), g, ok, os.Getgid())
	}
}

func TestMetadataOnlyFifoIsSpecial(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "auth.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	c := &collector{budget: 1 << 20}
	if e := c.collectFileLimit(fifo, fifo, true, 1<<20); e.Omitted != "special" {
		t.Fatalf("metadata-only FIFO recorded as %+v", e)
	}
}

// Directories a glob can't read are recorded (g6-F5, g7-F5): the glob itself
// ignores EACCES, so an unreadable rules dir looked empty on remote scans.
func TestGlobRecordsDeniedDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	home := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lock := func(p string) {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(p, 0o755) })
	}
	rules := mk(".codex/rules")                          // `*.rules` — the literal base
	nested := mk(".copilot/instructions/a")              // under `**/*.instructions.md`
	project := mk(".gemini/tmp/p1")                      // under a `*` segment
	mk(".gemini/tmp/p2/memory")                          // readable sibling
	vendor := mk(".copilot/instructions/node_modules/x") // vendor dir reached by `**`: skipped
	mk(".devin")
	devinRules := filepath.Join(home, ".devin", "rules")
	lock(rules)
	lock(nested)
	lock(project)
	lock(vendor)
	lock(filepath.Join(home, ".devin")) // rules can't even be stat'd

	snap := Collect(ProbeManifest{GlobPatterns: []string{
		filepath.Join(home, ".codex/rules/*.rules"),
		filepath.Join(home, ".copilot/instructions/**/*.instructions.md"),
		filepath.Join(home, ".gemini/tmp/*/memory/MEMORY.md"),
		filepath.Join(devinRules, "*.md"),
	}}, false)
	for _, d := range []string{rules, nested, project, filepath.Join(home, ".devin")} {
		if mode, ok := snap.DirectoryModes[d]; !ok || mode != 0 {
			t.Errorf("denied directory %s not recorded: %v", d, snap.DirectoryModes)
		}
	}
	if _, ok := snap.DirectoryModes[vendor]; ok {
		t.Error("a vendor dir the glob skips was walked")
	}
	if _, ok := snap.DirectoryModes[devinRules]; ok {
		t.Error("a directory that can't be stat'd has no mode to record")
	}
	if _, ok := snap.DirectoryModes[filepath.Join(home, ".gemini/tmp/p2/memory")]; ok {
		t.Error("a readable directory recorded as denied")
	}
}

// A folder inside a skill that can't be listed is recorded: a trailing `**`
// matches directories, but the glob never yields one it can't read, so a
// chmod-000 `locked/` in a skill looked empty remotely while a local walk
// reported it. The same inside a skill tree reached through a followed link.
func TestSkillGlobRecordsDeniedSubdirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	home := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lock := func(p string) {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(p, 0o755) })
	}
	skills := mk(".claude/skills")
	locked := mk(".claude/skills/s2/locked")
	inner := mk(".claude/skills/s2/locked/deeper")
	empty := mk(".claude/skills/s2/empty")
	vendor := mk(".claude/skills/s2/node_modules/x")
	if err := os.WriteFile(filepath.Join(locked, "a.js"), []byte("eval(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a skill linked in from a checkout elsewhere in the home
	linkedLocked := mk("src/ext-skill/locked")
	if err := os.WriteFile(filepath.Join(home, "src/ext-skill/SKILL.md"), []byte("# ext\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "src/ext-skill"), filepath.Join(skills, "ext")); err != nil {
		t.Fatal(err)
	}
	lock(inner)
	lock(locked)
	lock(vendor)
	lock(linkedLocked)

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	for _, d := range []string{locked, filepath.Join(skills, "ext", "locked")} {
		if mode, ok := snap.DirectoryModes[d]; !ok || mode != 0 {
			t.Errorf("denied directory %s not recorded: %v", d, snap.DirectoryModes)
		}
	}
	if _, ok := snap.DirectoryModes[vendor]; ok {
		t.Error("a vendor dir the glob skips was walked")
	}
	if _, ok := snap.DirectoryModes[inner]; ok {
		t.Error("a directory behind a denied one can't be stat'd")
	}
	if mode := snap.DirectoryModes[empty]; mode == 0 {
		t.Errorf("a readable directory recorded as denied: %v", snap.DirectoryModes)
	}
}

// A locked folder past the first 10,000 folders of a skills tree was never
// recorded (the denied walk stopped there), while a local walk reported it.
func TestSkillGlobRecordsDeniedDirsPastTheWalkBound(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	home := t.TempDir()
	big := filepath.Join(home, ".claude/skills/big")
	for i := 0; i < maxDeniedWalkDirs+50; i++ {
		if err := os.MkdirAll(filepath.Join(big, "d"+strconv.Itoa(100000+i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	locked := filepath.Join(big, "zzz", "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	if mode, ok := snap.DirectoryModes[locked]; !ok || mode != 0 {
		t.Errorf("denied directory past the bound not recorded: %v", ok)
	}
}

// A skill folder named like a vendor dir (`venv`, `node_modules`) holding a
// SKILL.md is collected like any skill; vendor dirs inside a skill, and one
// at the top holding no SKILL.md, are still skipped.
func TestSkillGlobCollectsVendorNamedSkills(t *testing.T) {
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
	skillMd := write("venv/skill.md", "# venv\n")
	run := write("venv/run.js", "eval(x)\n")
	nm := write("node_modules/SKILL.md", "# nm\n")
	inner := write("venv/node_modules/dep.js", "eval(x)\n")
	nested := write("s/venv/x.js", "eval(x)\n")
	plain := write(".venv/lib.js", "eval(x)\n")

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	for _, p := range []string{skillMd, run, nm} {
		if e, ok := snap.Files[p]; !ok || !e.Exists {
			t.Errorf("%s not collected", p)
		}
	}
	for _, p := range []string{inner, nested, plain} {
		if _, ok := snap.Files[p]; ok {
			t.Errorf("%s collected from a vendor dir", p)
		}
	}
}

// A skills-tree folder that can be listed but not searched (mode 644): its
// listing is recorded (links left out), so the CLI lists its names as a
// local walk does.
func TestSkillGlobRecordsUnsearchableListing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".claude/skills/t")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"SKILL.md", "run.js"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(dir, "ln")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	got := append([]string(nil), snap.Directories[dir]...)
	sort.Strings(got)
	if strings.Join(got, ",") != "SKILL.md,run.js,sub/" {
		t.Errorf("listing = %v", got)
	}
	if snap.DirectoryModes[dir] != 0o644 {
		t.Errorf("mode = %o", snap.DirectoryModes[dir])
	}
	// a searchable folder gets no listing from this
	if _, ok := snap.Directories[filepath.Join(home, ".claude/skills")]; ok {
		t.Error("a searchable folder's listing recorded")
	}
}

// A sticky world-writable directory is recorded as 01777, so a snapshot scan
// can tell it from a plain 0777 one (specialModeBits).
func TestDirectoryModesKeepTheStickyBit(t *testing.T) {
	root := t.TempDir()
	sticky := filepath.Join(root, "shared")
	plain := filepath.Join(root, "open")
	for _, d := range []string{sticky, plain} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plain, 0o777); err != nil {
		t.Fatal(err)
	}
	cmd := filepath.Join(sticky, "server")
	if err := os.WriteFile(cmd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap := ProbeSnapshot{Files: map[string]FileEntry{}, Directories: map[string][]string{}, DirectoryModes: map[string]int{}}
	c := &collector{budget: 1 << 20}
	c.collectPath(&snap, cmd, cmd, false, false)
	c.collectPath(&snap, plain, plain, false, true)
	recordAncestorModes(&snap, nil)
	if got := snap.DirectoryModes[sticky]; got != 0o1777 {
		t.Fatalf("sticky directory recorded as %o, want 1777", got)
	}
	if got := snap.DirectoryModes[plain]; got != 0o777 {
		t.Fatalf("plain directory recorded as %o, want 777", got)
	}
	if !Collect(ProbeManifest{}, false).SpecialModeBits {
		t.Fatalf("snapshot does not declare specialModeBits")
	}
}
