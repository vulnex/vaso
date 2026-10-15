package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
)

const defaultCommandTimeout = 5000 // ms

// Files larger than this are stat'd but their content is not embedded in the
// snapshot. This protects against filePath/glob entries that incidentally
// resolve to executables or large data files — without it, a single ~100 MB
// CLI binary in ~/.claude/local/claude would balloon the JSON snapshot past
// V8's ~512 MB max-string limit on the consuming Node side.
const maxFileContentBytes = 5 << 20 // 5 MiB — matches the CLI's MAX_SCAN_FILE_BYTES (src/core/file-limits.ts)

// maxConfigContentBytes bounds config files named explicitly in the manifest
// (filePaths/systemPaths). A local scan parses configs of any size, so a
// config padded past 5 MiB must not drop out of remote scans; binaries named
// there (CLI paths) keep the 5 MiB limit.
const maxConfigContentBytes = 32 << 20

var configExtensions = map[string]bool{".json": true, ".jsonc": true, ".json5": true, ".yaml": true, ".yml": true, ".toml": true, ".env": true, ".md": true}

// Total content budget for one snapshot. Real hosts with many agent plugins
// matched ~48k files / 700 MB through recursive skill globs, which the Node
// side cannot hold in one string. Past the budget, files are still recorded
// (exists + mode) but without content, and the snapshot is marked Truncated.
const maxTotalContentBytes = 256 << 20 // 256 MiB (JSON-escaped, still well under V8's ~512 MB string limit)

// Vendor / build-output / VCS directories skipped inside glob matches — kept
// in sync with EXCLUDED_DIRS in src/core/utils.ts (the local skill walk), so a
// remote scan sees the same files a local one analyses.
var excludedGlobDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".cache":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// Binary/asset types no check reads — recorded as metadata only so images,
// fonts, archives and compiled artefacts in skill trees don't spend the budget.
var metadataOnlyExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".mov": true, ".wav": true, ".webm": true,
	".zip": true, ".gz": true, ".tgz": true, ".tar": true, ".jar": true, ".7z": true, ".pdf": true,
	".node": true, ".so": true, ".dylib": true, ".dll": true, ".exe": true, ".wasm": true, ".bin": true,
	".pyc": true, ".db": true, ".sqlite": true, ".sqlite3": true,
}

// Compiled artefacts read inside skill trees: IOC-003/007 hash a skill's
// bundled helpers (droppers ship as .node/.so/.exe), within the 5 MiB cap.
var skillBinaryExtensions = map[string]bool{
	".node": true, ".so": true, ".dylib": true, ".dll": true, ".exe": true, ".bin": true,
}

// Build output kept inside skill trees, where `dist/index.js` is usually the
// code SKILL.md runs — mirrors BUILD_OUTPUT_DIRS / keepBuildOutput in src/core/utils.ts.
var skillTreeBuildDirs = map[string]bool{"dist": true, "build": true}

// isSkillPattern reports whether a glob walks a skills tree (`…/skills/**`).
func isSkillPattern(pattern string) bool {
	return strings.Contains(filepath.ToSlash(pattern), "/skills/")
}

// collector carries per-snapshot state (the remaining content budget).
type collector struct {
	budget    int64
	truncated bool
	// inSkillTree is set while collecting a skills glob's matches.
	inSkillTree bool
}

// inExcludedDir reports whether match lies under an excluded directory that
// the glob reached through a wildcard. Segments above the pattern's static
// base (a user named "build") and directories the pattern names literally
// (npm package.json globs that target .../node_modules/<pkg>/package.json)
// don't count.
func inExcludedDir(pattern, match string) bool {
	slashPattern := filepath.ToSlash(pattern)
	base, _ := doublestar.SplitPattern(slashPattern)
	rel, err := filepath.Rel(filepath.FromSlash(base), match)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	literal := make(map[string]bool)
	for _, seg := range strings.Split(slashPattern, "/") {
		literal[seg] = true
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	skills := isSkillPattern(pattern)
	for _, seg := range parts[:len(parts)-1] {
		if excludedGlobDirs[seg] && !literal[seg] && !(skills && skillTreeBuildDirs[seg]) {
			return true
		}
	}
	return false
}

// Common per-user bin dirs that hold CLIs we care about. Non-interactive SSH
// sessions inherit a minimal PATH that excludes these, so we prepend them
// before running version/which probes.
var userBinDirs = []string{
	".local/bin",
	".bun/bin",
	".cargo/bin",
	".npm-global/bin",
	".volta/bin",
	// Self-installed agent CLIs whose installer only edits interactive rc files;
	// ahead of nvm so a native install wins over a stale npm copy, as in a shell.
	".abacusai/bin",
	".nvm/current/bin",
	".claude/local",
	".opencode/bin",
	"bin",
}

// Package-manager bin dirs missing from a minimal non-interactive PATH.
var systemBinDirs = []string{"/opt/homebrew/bin", "/usr/local/bin", "/snap/bin"}

// buildAugmentedPath prepends each home's user bin dirs to PATH (current-user
// home first), so commands like `claude --version` resolve under non-interactive
// SSH where rc-file PATH additions don't apply.
//
// As root the user dirs go last: a bare name (`which`, `ps`, an agent CLI)
// must resolve to a system binary before any copy a local user planted in
// their own ~/.local/bin. runCommand then decides who a resolved binary runs as.
func buildAugmentedPath(homes []UserHome, basePath string) string {
	var userDirs []string
	for _, h := range homes {
		for _, d := range userBinDirs {
			userDirs = append(userDirs, filepath.Join(h.Path, d))
		}
	}
	var parts []string
	if !runningAsRoot() {
		parts = append(parts, userDirs...)
	}
	if basePath != "" {
		parts = append(parts, basePath)
	}
	// Package-manager bin dirs a login shell adds (Homebrew's path_helper /
	// shellenv, snapd's profile.d) but a non-interactive SSH session lacks —
	// appended after the session PATH so its order still wins.
	present := make(map[string]bool)
	for _, d := range filepath.SplitList(basePath) {
		present[d] = true
	}
	for _, d := range systemBinDirs {
		if !present[d] {
			parts = append(parts, d)
		}
	}
	if runningAsRoot() {
		parts = append(parts, userDirs...)
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

// rootChildPath is the PATH a command run as root gets: only directories no
// other user can write, so a root-owned script's `#!/usr/bin/env node` can't
// pick up a node binary a local user dropped into their own bin dir.
func rootChildPath(augmentedPath string) string {
	var safe []string
	for _, d := range filepath.SplitList(augmentedPath) {
		if d != "" && rootSafe(d) {
			safe = append(safe, d)
		}
	}
	return strings.Join(safe, string(os.PathListSeparator))
}

// Collect executes the probe manifest and returns a snapshot.
func Collect(manifest ProbeManifest, escalate bool) ProbeSnapshot {
	MaybeEscalate(escalate)

	priv := DetectPrivilege()
	homes := DiscoverUserHomes(priv)

	hostname, _ := os.Hostname()
	homedir, _ := os.UserHomeDir()

	snapshot := ProbeSnapshot{
		Version:        1,
		ProbeVersion:   version,
		Hostname:       hostname,
		Platform:       runtime.GOOS,
		Homedir:        homedir,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Privilege:      priv,
		Files:          make(map[string]FileEntry),
		Directories:    make(map[string][]string),
		CommandOutputs: make(map[string]CommandOutput),
		Env:            make(map[string]string),
		DirectoryModes: make(map[string]int),
		Symlinks:       make(map[string]string),
		Owners:         make(map[string][2]int),
		PrivateGroups:  collectPrivateGroups(),
	}
	c := &collector{budget: maxTotalContentBytes}

	// Track scanned users
	for _, h := range homes {
		priv.ScannedUsers = append(priv.ScannedUsers, h.Username)
	}
	snapshot.Privilege = priv

	// Expand and collect file paths
	expandedPaths := expandPaths(manifest.FilePaths, homes)
	for _, p := range expandedPaths {
		c.collectPath(&snapshot, p, false, true)
	}

	// Expand and collect system paths (not expanded per-user)
	for _, p := range manifest.SystemPaths {
		c.collectPath(&snapshot, p, false, true)
	}

	// Expand and collect glob patterns
	expandedGlobs := expandPaths(manifest.GlobPatterns, homes)
	for _, pattern := range expandedGlobs {
		c.inSkillTree = isSkillPattern(pattern)
		// Never descend into symlinked directories: a local readdir lists the
		// link without following it, so following here duplicated every file
		// a skill symlinks in from elsewhere. The link itself still matches.
		matches, err := doublestar.FilepathGlob(pattern, doublestar.WithNoFollow())
		if err != nil {
			continue
		}
		for _, match := range matches {
			if inExcludedDir(pattern, match) {
				continue
			}
			recordSymlink(snapshot.Symlinks, match)
			if _, exists := snapshot.Files[match]; !exists {
				c.collectPath(&snapshot, match, false, false)
			}
		}
		c.followLinkedTrees(&snapshot, pattern, matches, false)
		if c.inSkillTree {
			c.collectUnlistableSkills(&snapshot, pattern)
		}
	}
	c.inSkillTree = false

	// Metadata-only globs: existence + mode, never content
	for _, pattern := range expandPaths(manifest.MetadataGlobPatterns, homes) {
		matches, err := doublestar.FilepathGlob(pattern, doublestar.WithNoFollow())
		if err != nil {
			continue
		}
		for _, match := range matches {
			if inExcludedDir(pattern, match) {
				continue
			}
			recordSymlink(snapshot.Symlinks, match)
			if _, exists := snapshot.Files[match]; !exists {
				c.collectPath(&snapshot, match, true, false)
			}
		}
		c.followLinkedTrees(&snapshot, pattern, matches, true)
	}

	// Expand and collect directory listings. Only non-nil listings are stored:
	// a nil result means the directory doesn't exist or can't be read, and
	// inserting a key with a nil value would cause downstream consumers to
	// report the directory as "present". A directory that exists but can't be
	// listed (mode 000) still gets its mode recorded, so it is present
	// remotely the way it is locally.
	expandedDirs := expandPaths(manifest.DirectoryListings, homes)
	for _, dir := range expandedDirs {
		if listing := collectDirectory(dir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[dir] = listing
		}
		recordDirMode(&snapshot, dir)
	}

	// Collect system directory listings (not expanded per-user)
	for _, dir := range manifest.SystemDirListings {
		if listing := collectDirectory(dir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[dir] = listing
		}
		recordDirMode(&snapshot, dir)
	}
	// Home dirs gate traversal for everything beneath them (parent-directory
	// mitigation on the TS side needs their real modes).
	for _, h := range homes {
		recordDirMode(&snapshot, h.Path)
	}

	// Run allowed commands with PATH extended to include per-user bin dirs.
	// Each output is stored under both its manifest ID (e.g. "nemoclaw-help")
	// and its natural "<cmd> <args>" key (e.g. "nemoclaw help") so the TS-side
	// snapshot lookup can resolve ambiguous shared-basename commands precisely.
	cmdPath := buildAugmentedPath(homes, os.Getenv("PATH"))
	for _, cmdReq := range manifest.Commands {
		// If any arg uses ~, run the command once per discovered user with
		// that user's home substituted. Each invocation's natural-key entry
		// (cmd + resolved-args) is preserved so the TS-side fs.exec lookup,
		// which constructs the full path itself, still matches. The id-keyed
		// entry only retains the last user's output — TS callers should
		// always go through the natural key when paths are user-scoped.
		argSets := expandArgsPerUser(cmdReq.Args, homes)
		if cmdReq.ForEach != nil {
			argSets = expandForEach(cmdReq, snapshot.CommandOutputs)
		}
		for _, args := range argSets {
			req := cmdReq
			req.Args = args
			out := runCommand(req, cmdPath)
			snapshot.CommandOutputs[cmdReq.ID] = out
			naturalKey := strings.TrimSpace(req.Cmd + " " + strings.Join(req.Args, " "))
			if naturalKey != "" && naturalKey != cmdReq.ID {
				if _, exists := snapshot.CommandOutputs[naturalKey]; !exists {
					snapshot.CommandOutputs[naturalKey] = out
				}
			}
		}
	}

	// Record the mode of every ancestor of what was collected, so the TS side
	// can tell whether a parent directory blocks other users (parent-directory
	// mitigation) exactly as a local scan does.
	recordAncestorModes(&snapshot)

	// Collect filtered environment variables
	snapshot.Env = collectEnv(manifest.EnvPrefixes)
	snapshot.Truncated = c.truncated

	return snapshot
}

// expandArgsPerUser returns one resolved arg vector per user when any arg
// starts with ~/, otherwise the original args unchanged in a single-element
// slice. Mirrors expandPaths's per-user fan-out so per-user-scoped tools
// (plutil, defaults read on user preference plists) can be probed under
// --all-users without forcing every adapter to specify multiple manifest
// entries.
func expandArgsPerUser(args []string, homes []UserHome) [][]string {
	needsExpansion := false
	for _, a := range args {
		if strings.HasPrefix(a, "~/") || a == "~" {
			needsExpansion = true
			break
		}
	}
	if !needsExpansion {
		return [][]string{args}
	}
	var result [][]string
	for _, h := range homes {
		expanded := make([]string, len(args))
		for i, a := range args {
			if strings.HasPrefix(a, "~/") || a == "~" {
				expanded[i] = filepath.Join(h.Path, strings.TrimPrefix(a, "~"))
			} else {
				expanded[i] = a
			}
		}
		result = append(result, expanded)
	}
	return result
}

// expandPaths replaces ~ with each discovered user home directory.
// envPathPrefix matches a manifest path rooted at an environment variable:
// `${PICOCLAW_HOME}/config.json`, `${XDG_CONFIG_HOME}/opencode/**`.
var envPathPrefix = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(/.*)?$`)

// expandEnvPath resolves `${NAME}` + rest from the probe's environment — the
// scanned user's, where an agent relocated with PICOCLAW_HOME or
// XDG_CONFIG_HOME keeps its files. Unset or relative values expand to
// nothing; a leading `~` is the probe user's home.
func expandEnvPath(name, rest string) (string, bool) {
	val := strings.TrimSpace(os.Getenv(name))
	if val == "" {
		return "", false
	}
	if val == "~" || strings.HasPrefix(val, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		val = filepath.Join(home, strings.TrimPrefix(val, "~"))
	}
	if !filepath.IsAbs(val) {
		return "", false
	}
	// Clean the whole path: a twin may step out of the variable's directory
	// (`${ZEROCLAW_DATA_DIR}/../.zeroclaw/` — the legacy config next to a data
	// dir), and snapshot keys must match the paths adapters join.
	return filepath.Clean(filepath.Clean(val) + rest), true
}

func expandPaths(paths []string, homes []UserHome) []string {
	var expanded []string
	for _, p := range paths {
		if m := envPathPrefix.FindStringSubmatch(p); m != nil {
			if exp, ok := expandEnvPath(m[1], m[2]); ok {
				expanded = append(expanded, exp)
			}
			continue
		}
		if strings.HasPrefix(p, "~/") || p == "~" {
			for _, h := range homes {
				exp := filepath.Join(h.Path, strings.TrimPrefix(p, "~"))
				expanded = append(expanded, exp)
			}
		} else {
			expanded = append(expanded, p)
		}
	}
	return expanded
}

// collectFile reads a file and returns its content and mode. Content is
// omitted (Exists+Mode only, ContentOmitted set) for metadata-only requests,
// files over maxFileContentBytes, and once the snapshot's total content budget
// is spent — enough for adapters that only need presence or permissions.
func (c *collector) collectFile(path string, metadataOnly bool) FileEntry {
	return c.collectFileLimit(path, metadataOnly, maxFileContentBytes)
}

func (c *collector) collectFileLimit(path string, metadataOnly bool, limit int64) FileEntry {
	info, err := os.Stat(path)
	if err != nil {
		return FileEntry{Exists: false, Denied: os.IsPermission(err)}
	}

	mode := int(info.Mode().Perm())
	omitted := func(reason string) FileEntry {
		return FileEntry{Exists: true, Mode: mode, ContentOmitted: true, Omitted: reason}
	}

	ext := strings.ToLower(filepath.Ext(path))
	assetOnly := metadataOnlyExtensions[ext] && !(c.inSkillTree && skillBinaryExtensions[ext])
	switch {
	case metadataOnly:
		return omitted("metadata")
	case assetOnly:
		return omitted("asset")
	case info.Size() > limit:
		return omitted("size")
	}
	if info.Size() > c.budget {
		c.truncated = true
		return omitted("budget")
	}

	// Only regular files have content. A FIFO blocks forever and a device
	// such as /dev/zero (size 0 to Stat) never ends; either can be planted
	// in a skill directory. The check is on the opened file, so swapping the
	// path between Stat and Open doesn't get around it.
	if !info.Mode().IsRegular() {
		return omitted("special")
	}
	f, err := openForRead(path)
	if err != nil {
		// Present but unreadable (mode 000, an ACL): say so — shipping it as
		// an empty file would let the CLI judge content that isn't there.
		return FileEntry{Exists: true, Mode: mode, Denied: true}
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !opened.Mode().IsRegular() {
		return omitted("special")
	}
	// Bounded even if the file grows after Stat
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return FileEntry{Exists: true, Mode: mode}
	}
	if int64(len(content)) > limit {
		return omitted("size")
	}
	return c.fileContent(content, mode)
}

// fileContent stores text as-is and anything that is not valid UTF-8 as
// base64, charging the budget for what is actually shipped.
func (c *collector) fileContent(content []byte, mode int) FileEntry {
	entry := FileEntry{Content: string(content), Mode: mode, Exists: true}
	if !utf8.Valid(content) {
		entry.Content = base64.StdEncoding.EncodeToString(content)
		entry.Encoding = "base64"
	}
	c.budget -= jsonSize(entry.Content)
	return entry
}

// jsonSize is what s costs in the snapshot JSON: the encoder escapes <, >, &,
// control characters and U+2028/2029 as \uXXXX (6 bytes) and quotes and
// backslashes as 2. Charging raw bytes let 129 MiB of such text become a
// 519 MiB snapshot, over what the CLI accepts, without being marked truncated.
func jsonSize(s string) int64 {
	n := int64(len(s))
	for i := 0; i < len(s); i++ {
		switch b := s[i]; {
		case b == '<' || b == '>' || b == '&' || b < 0x20:
			n += 5
		case b == '"' || b == '\\':
			n++
		case b == 0xE2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xA8 || s[i+2] == 0xA9):
			n += 3 // 3-byte rune → 6-byte escape
		}
	}
	return n
}

// collectPath records p as a directory (mode, plus its listing when listDir)
// or as a file. Directories used to be stored as file entries (os.ReadFile
// fails, Exists+Mode kept), which made them look like files remotely.
func (c *collector) collectPath(snapshot *ProbeSnapshot, p string, metadataOnly, listDir bool) {
	info, err := os.Stat(p)
	if err == nil {
		recordOwner(snapshot, p, info)
	}
	if err == nil && info.IsDir() {
		snapshot.DirectoryModes[p] = int(info.Mode().Perm())
		if listDir {
			if listing := collectDirectory(p, snapshot.Symlinks); listing != nil {
				snapshot.Directories[p] = listing
			}
		}
		return
	}
	limit := int64(maxFileContentBytes)
	if listDir && configExtensions[strings.ToLower(filepath.Ext(p))] {
		limit = maxConfigContentBytes // a config named explicitly, not a glob match
	}
	snapshot.Files[p] = c.collectFileLimit(p, metadataOnly, limit)
}

// recordAncestorModes stats each parent directory of every collected file and
// directory (once each) up to the filesystem root.
func recordAncestorModes(snapshot *ProbeSnapshot) {
	seen := make(map[string]bool)
	visit := func(p string) {
		for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
			if seen[dir] {
				return
			}
			seen[dir] = true
			if _, ok := snapshot.DirectoryModes[dir]; !ok {
				recordDirMode(snapshot, dir)
			}
			if parent := filepath.Dir(dir); parent == dir {
				return
			}
		}
	}
	for p, e := range snapshot.Files {
		// A denied file's parents too: the unreadable directory that denied
		// it is what a local scan runs into (EACCES, not "missing")
		if e.Exists || e.Denied {
			visit(p)
		}
	}
	for d := range snapshot.Directories {
		visit(d)
	}
}

// recordDirMode stores a directory's permission bits when it can be stat'd.
func recordDirMode(snapshot *ProbeSnapshot, dir string) {
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		snapshot.DirectoryModes[dir] = int(info.Mode().Perm())
		recordOwner(snapshot, dir, info)
	}
}

// recordOwner stores a path's [uid, gid] when the platform reports it.
func recordOwner(snapshot *ProbeSnapshot, p string, info os.FileInfo) {
	if snapshot.Owners == nil {
		return
	}
	if uid, gid, ok := fileOwner(info); ok {
		snapshot.Owners[p] = [2]int{uid, gid}
	}
}

// collectDirectory lists the entries of a directory. Returns nil if the
// directory doesn't exist or cannot be read; the caller treats that as a
// signal to skip storing the entry entirely so that consumers don't mistake
// "we tried to list this and it wasn't there" for "this directory exists".
func collectDirectory(dir string, symlinks map[string]string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	// Empty but readable directory: return a non-nil empty slice so the caller
	// can distinguish "exists, no entries" from "doesn't exist".
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		if entry.Type()&os.ModeSymlink != 0 {
			recordSymlink(symlinks, filepath.Join(dir, name))
		}
		names = append(names, name)
	}
	return names
}

// maxLinkDepth bounds how many symlinks deep followLinkedTrees goes.
const maxLinkDepth = 8

// followLinkedTrees collects, under the link's own path, the directories a
// `<root>/**` glob reached only as symlinks pointing outside root — skills
// are often installed as a link into a checkout elsewhere, and the agent
// loads what it points to. A link back into the tree (or to a parent of it)
// is skipped: that content is already collected. Mirrors walkSkillTree in
// src/core/skill-walk.ts so local and remote scans read the same files.
func (c *collector) followLinkedTrees(snapshot *ProbeSnapshot, pattern string, matches []string, metadataOnly bool) {
	if !strings.HasSuffix(filepath.ToSlash(pattern), "/**") {
		return
	}
	rootReal, err := filepath.EvalSymlinks(strings.TrimSuffix(filepath.ToSlash(pattern), "/**"))
	if err != nil {
		return
	}
	visited := map[string]bool{rootReal: true}
	c.followFrom(snapshot, pattern, matches, []string{rootReal}, visited, 0, metadataOnly)
}

func (c *collector) followFrom(snapshot *ProbeSnapshot, pattern string, matches []string, roots []string, visited map[string]bool, depth int, metadataOnly bool) {
	if depth >= maxLinkDepth {
		return
	}
	for _, m := range matches {
		info, err := os.Lstat(m)
		if err != nil || info.Mode()&os.ModeSymlink == 0 || inExcludedDir(pattern, m) {
			continue
		}
		real, err := filepath.EvalSymlinks(m)
		if err != nil || visited[real] || relatedToAny(real, roots) {
			continue
		}
		if st, err := os.Stat(m); err != nil || !st.IsDir() {
			continue // a file link was collected (followed) by the glob itself
		}
		visited[real] = true
		sub, err := doublestar.FilepathGlob(filepath.Join(m, "**"), doublestar.WithNoFollow())
		if err != nil {
			continue
		}
		for _, sm := range sub {
			if inExcludedDir(pattern, sm) {
				continue
			}
			recordSymlink(snapshot.Symlinks, sm)
			if _, exists := snapshot.Files[sm]; !exists {
				c.collectPath(snapshot, sm, metadataOnly, false)
			}
		}
		c.followFrom(snapshot, pattern, sub, append(append([]string{}, roots...), real), visited, depth+1, metadataOnly)
	}
}

// relatedToAny reports whether p is inside one of dirs or contains one.
func relatedToAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if within(p, d) || within(d, p) {
			return true
		}
	}
	return false
}

func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// recordSymlink stores p's link target when p is a symlink.
func recordSymlink(symlinks map[string]string, p string) {
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return
	}
	if target, err := os.Readlink(p); err == nil {
		symlinks[p] = target
	}
}

// resolveBinary searches augmentedPath for a bare command name. Go's
// exec.LookPath uses the parent process's PATH, not the env we'd attach via
// cmd.Env, so for binaries that only live under per-user bin dirs (e.g.
// ~/.local/bin/claude) we must resolve the absolute path ourselves.
func resolveBinary(cmd, augmentedPath string) string {
	if filepath.IsAbs(cmd) || strings.Contains(cmd, "/") {
		return cmd
	}
	for _, dir := range strings.Split(augmentedPath, string(os.PathListSeparator)) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, cmd)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return cmd
}

// runCommand executes a command if it is on the allowlist. The provided
// augmented PATH is searched for bare commands and also propagated to the
// child process so spawned scripts (e.g. node-based CLI shims) can resolve
// their own dependencies.
// setEnv replaces or appends KEY=value in an environment slice.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func runCommand(req CommandRequest, augmentedPath string) CommandOutput {
	if !IsAllowed(req.Cmd) {
		return CommandOutput{
			Stderr:   fmt.Sprintf("command %q not in allowlist", req.Cmd),
			ExitCode: -1,
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	resolved := resolveBinary(req.Cmd, augmentedPath)
	if InstallsOnRun(req.Cmd, resolved) {
		return CommandOutput{
			Stderr:   fmt.Sprintf("%s is an install-on-run wrapper; not executed", resolved),
			ExitCode: -1,
		}
	}
	cmd := exec.CommandContext(ctx, resolved, req.Args...)

	// As root, nothing another user controls runs with root's privileges: a
	// binary owned by a user runs as that user (privileges dropped), and a
	// root-owned one only when no one else could have replaced it.
	childPath := augmentedPath
	dropUID, dropGID := -1, -1
	if runningAsRoot() {
		real, err := filepath.EvalSymlinks(resolved)
		info, statErr := os.Stat(real)
		if err != nil || statErr != nil {
			return CommandOutput{Stderr: fmt.Sprintf("%s not found", req.Cmd), ExitCode: -1}
		}
		if uid, gid, ok := fileOwner(info); ok && uid != 0 {
			dropUID, dropGID = uid, gid
			dropTo(cmd, uid, gid)
		} else if !rootSafe(real) {
			return CommandOutput{
				Stderr:   fmt.Sprintf("%s is writable by a non-root user; not run as root", real),
				ExitCode: -1,
			}
		} else {
			childPath = rootChildPath(augmentedPath)
		}
	}

	env := os.Environ()
	if childPath != "" {
		env = setEnv(env, "PATH", childPath)
	}
	if req.IsolateHome {
		home, err := os.MkdirTemp("", "vaso-exec-")
		if err == nil {
			defer os.RemoveAll(home)
			if dropUID >= 0 {
				_ = os.Chown(home, dropUID, dropGID) // the dropped user must be able to use it
			}
			for k, v := range map[string]string{
				"HOME":            home,
				"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
				"XDG_DATA_HOME":   filepath.Join(home, ".local", "share"),
				"XDG_CACHE_HOME":  filepath.Join(home, ".cache"),
				"XDG_STATE_HOME":  filepath.Join(home, ".local", "state"),
			} {
				env = setEnv(env, k, v)
			}
			cmd.Dir = home
		}
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return CommandOutput{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
}

// secretEnvParts are name segments (split on "_") that mark a credential.
// Their values never leave the host: checks only need to know such a variable
// is set. Names ending in a location suffix (…_KEY_PATH, …_TOKEN_FILE) hold a
// path, not the secret, and adapters need them to find credential files.
var secretEnvParts = map[string]bool{
	"KEY": true, "KEYS": true, "APIKEY": true, "TOKEN": true, "TOKENS": true,
	"SECRET": true, "SECRETS": true, "PASS": true, "PASSWD": true, "PASSWORD": true,
	"PASSPHRASE": true, "CREDENTIAL": true, "CREDENTIALS": true, "AUTH": true,
	"COOKIE": true, "SESSION": true,
}
var locationEnvSuffix = map[string]bool{"PATH": true, "DIR": true, "FILE": true, "HOME": true, "URL": true}

func isSecretEnvName(name string) bool {
	parts := strings.Split(strings.ToUpper(name), "_")
	if locationEnvSuffix[parts[len(parts)-1]] {
		return false
	}
	for _, p := range parts {
		if secretEnvParts[p] {
			return true
		}
	}
	return false
}

// redactedEnvValue replaces the value of a credential-bearing variable.
const redactedEnvValue = "[redacted]"

// collectEnv returns environment variables that match any of the given
// prefixes, with credential-bearing values redacted.
func collectEnv(prefixes []string) map[string]string {
	result := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := parts[1]
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				if isSecretEnvName(key) {
					val = redactedEnvValue
				}
				result[key] = val
				break
			}
		}
	}
	return result
}

// DefaultManifest returns a minimum-viable manifest used when the probe is
// invoked without -manifest. Operators should prefer `vaso probe manifest`
// (emitted by the VASO CLI) for full coverage — this fallback only contains
// the most common config paths and may lag the CLI-emitted manifest.
func DefaultManifest() ProbeManifest {
	return ProbeManifest{
		FilePaths: []string{
			// OpenClaw
			"~/.openclaw/config.json",
			"~/.openclaw/config.yaml",
			"~/.openclaw/config.yml",
			// NanoClaw
			"~/.nanoclaw/config.json",
			"~/.nanoclaw/.env",
			// PicoClaw
			"~/.picoclaw/config.json",
			// IronClaw
			"~/.ironclaw/config.toml",
			// Nanobot
			"~/.nanobot/config.json",
			// ZeroClaw
			"~/.zeroclaw/config.toml",
			// NemoClaw
			"~/.nemoclaw/config.json",
			"~/.nemoclaw/config.yaml",
			// Hermes
			"~/.hermes/config.yaml",
			"~/.hermes/.env",
			"~/.hermes/credentials.json",
			// Claude Code
			"~/.claude/settings.json",
			"~/.claude/settings.local.json",
			"~/.claude/.credentials.json",
			"~/.claude/mcp.json",
			"~/.claude.json",
			// Codex
			"~/.codex/config.toml",
			"~/.codex/auth.json",
			// MCP host configs
			"~/Library/Application Support/Claude/claude_desktop_config.json",
			"~/.config/Claude/claude_desktop_config.json",
			"~/.cursor/mcp.json",
			"~/.codeium/windsurf/mcp_config.json",
		},
		GlobPatterns: []string{
			"~/.openclaw/profiles/*.json",
			"~/.openclaw/profiles/*.yaml",
			"~/.openclaw/sub-agents/**/*.json",
			"~/.nanoclaw/profiles/*.json",
			"~/.ironclaw/**/*.toml",
			"~/.zeroclaw/**/*.toml",
			"~/.nemoclaw/**/*.yaml",
			"~/.hermes/skills/**",
			"~/.hermes/optional-skills/**",
		},
		Commands: []CommandRequest{
			{ID: "openclaw-version", Cmd: "openclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nanoclaw-version", Cmd: "nanoclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "picoclaw-version", Cmd: "picoclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "ironclaw-version", Cmd: "ironclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nanobot-version", Cmd: "nanobot", Args: []string{"--version"}, Timeout: 5000},
			{ID: "zeroclaw-version", Cmd: "zeroclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nemoclaw-version", Cmd: "nemoclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "hermes-version", Cmd: "hermes", Args: []string{"version"}, Timeout: 5000},
			{ID: "docker-ps", Cmd: "docker", Args: []string{"ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"}, Timeout: 10000},
			{ID: "netstat-listen", Cmd: "netstat", Args: []string{"-tlnp"}, Timeout: 5000},
			{ID: "ps-agents", Cmd: "ps", Args: []string{"aux"}, Timeout: 5000},
			{ID: "crontab-list", Cmd: "crontab", Args: []string{"-l"}, Timeout: 5000},
			{ID: "hostname", Cmd: "hostname", Args: []string{}, Timeout: 5000},
			{ID: "uname", Cmd: "uname", Args: []string{"-a"}, Timeout: 5000},
			{ID: "id", Cmd: "id", Args: []string{}, Timeout: 5000},
		},
		DirectoryListings: []string{
			"~/.openclaw",
			"~/.nanoclaw",
			"~/.picoclaw",
			"~/.ironclaw",
			"~/.nanobot",
			"~/.zeroclaw",
			"~/.nemoclaw",
			"~/.hermes",
			"~/.hermes/skills",
			"~/.hermes/optional-skills",
			"~/.claude",
			"~/.claude/skills",
			"~/.claude/plugins",
			"~/.claude/agents",
			"~/.codex",
			"~/.vaso/plugins",
		},
		EnvPrefixes: []string{
			"OPENCLAW_",
			"NANOCLAW_",
			"PICOCLAW_",
			"IRONCLAW_",
			"NANOBOT_",
			"ZEROCLAW_",
			"NEMOCLAW_",
			"HERMES_",
			"CLAUDE_",
			"ANTHROPIC_",
			"CODEX_",
			"OPENAI_",
			"MCP_",
			"VASO_",
		},
		SystemPaths: []string{
			"/etc/openclaw/config.json",
			"/etc/nanoclaw/config.json",
			"/etc/ironclaw/config.toml",
			"/etc/zeroclaw/config.toml",
		},
		SystemDirListings: []string{
			"/etc/openclaw",
			"/etc/nanoclaw",
		},
	}
}

// forEachValue is what a substituted item field may look like: an identifier
// (sandbox and workspace names), never an option (leading '-') or a path.
var forEachValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

const maxForEachItems = 100

// expandForEach builds one argument list per item of the JSON array produced
// by an earlier command (req.ForEach.From), replacing each {field} placeholder
// in req.Args with the item's value. A field the item omits (or leaves empty)
// takes its value from spec.Defaults when there is one — the same fallback the
// local scan applies, so remote and local runs query the same items. Items
// with a malformed or undefaulted missing field are skipped; a failed or
// non-JSON source yields no runs.
func expandForEach(req CommandRequest, outputs map[string]CommandOutput) [][]string {
	spec := req.ForEach
	src, ok := outputs[spec.From]
	if !ok || src.ExitCode != 0 {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(src.Stdout), &parsed); err != nil {
		return nil
	}
	items, isList := parsed.([]interface{})
	if !isList {
		obj, isObj := parsed.(map[string]interface{})
		if !isObj {
			return nil
		}
		if items, isList = obj[spec.Array].([]interface{}); !isList {
			return nil
		}
	}
	var out [][]string
	for _, item := range items {
		if len(out) >= maxForEachItems {
			break
		}
		fields, isObj := item.(map[string]interface{})
		if !isObj {
			continue
		}
		values := make(map[string]string, len(spec.Fields))
		valid := true
		for _, f := range spec.Fields {
			v, isStr := fields[f].(string)
			if raw, present := fields[f]; !present || raw == nil || (isStr && v == "") {
				v, isStr = spec.Defaults[f]
			}
			if !isStr || !forEachValue.MatchString(v) {
				valid = false
				break
			}
			values[f] = v
		}
		if !valid {
			continue
		}
		args := make([]string, len(req.Args))
		for i, a := range req.Args {
			for f, v := range values {
				a = strings.ReplaceAll(a, "{"+f+"}", v)
			}
			args[i] = a
		}
		out = append(out, args)
	}
	return out
}

// collectUnlistableSkills handles a skill directory that can be entered but
// not listed (mode 111): a glob sees nothing in it, yet the agent still loads
// SKILL.md by name. Its mode is recorded and SKILL.md and package.json collected, as a local
// scan reads it. The root is the pattern's literal prefix before "/**".
func (c *collector) collectUnlistableSkills(snapshot *ProbeSnapshot, pattern string) {
	i := strings.Index(pattern, "/**")
	if i <= 0 || strings.ContainsAny(pattern[:i], "*?[{") {
		return
	}
	root := pattern[:i]
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.ReadDir(dir); err == nil || !os.IsPermission(err) {
			continue
		}
		recordDirMode(snapshot, dir)
		// The files a local scan reads by name in such a dir: SKILL.md (the
		// agent loads it) and package.json (IOC-004 publisher, SKL-011 deps)
		for _, name := range []string{"SKILL.md", "package.json"} {
			p := filepath.Join(dir, name)
			if _, exists := snapshot.Files[p]; !exists {
				c.collectPath(snapshot, p, false, false)
			}
		}
	}
}
