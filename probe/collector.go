package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
)

const defaultCommandTimeout = 5000 // ms

// waitDelay is how long a command's output pipes may stay open after it
// exits (held by a background child) or after its timeout kill.
const waitDelay = 500 * time.Millisecond

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
	".icns": true, ".tiff": true, ".tif": true, ".heic": true, ".avif": true,
	".bz2": true, ".xz": true, ".zst": true, ".lz4": true, ".dmg": true, ".iso": true,
}

// Compiled artefacts read inside skill trees: IOC-003/007 hash a skill's
// bundled helpers (droppers ship as .node/.so/.exe), within the 5 MiB cap.
var skillBinaryExtensions = map[string]bool{
	".node": true, ".so": true, ".dylib": true, ".dll": true, ".exe": true, ".bin": true,
}

// Build output kept inside skill trees, where `dist/index.js` is usually the
// code SKILL.md runs — mirrors BUILD_OUTPUT_DIRS / keepBuildOutput in src/core/utils.ts.
var skillTreeBuildDirs = map[string]bool{"dist": true, "build": true}

// skillSegment is a directory name a skills tree is kept under: skills,
// skills-cursor, custom_skills, installed_skills, open-skills,
// optional-skills (every skills glob in the manifest has one).
var skillSegment = regexp.MustCompile(`(?i)^(?:.*[-_.])?skills?(?:[-_.].*)?$`)

// isSkillPattern reports whether a glob walks a skills tree
// (`…/skills/**`, `~/.cursor/skills-cursor/**`, `${HERMES_HOME}/optional-skills/**`).
func isSkillPattern(pattern string) bool {
	return hasSkillSegment(filepath.ToSlash(pattern))
}

// hasSkillSegment: a directory of the slash path p (not its last part) is a
// skills directory.
func hasSkillSegment(p string) bool {
	parts := strings.Split(p, "/")
	for _, seg := range parts[:len(parts)-1] {
		if skillSegment.MatchString(seg) {
			return true
		}
	}
	return false
}

// collector carries per-snapshot state (the remaining content budget).
type collector struct {
	budget    int64
	truncated bool
	// inSkillTree is set while collecting a skills glob's matches.
	inSkillTree bool
	// configTree is set while collecting a tree an agent's config names
	// (configRoots): walked as a skill tree, but its content is disguised like
	// a config's — the directory is wherever the config says.
	configTree bool
	// treeHome is the home of the user whose config names the tree being
	// walked: links leading where no skills tree is walked (treeAllowed —
	// another user's home, an OS directory, a credential store) are neither
	// followed nor read
	treeHome string
	// explicit are the manifest's own file and system paths (their symlink
	// chains and real parents are recorded, see recordExplicitLinks).
	explicit []string
	// homes are the scanned users' home directories (scrubbable)
	homes []string
	// disguised maps each secret scrubbed from file content to its stand-in,
	// so a key repeated across files stays one key (secret_scrub.go)
	disguised map[string]string
	// inFile: the values disguised in the file being scrubbed, and their stand-ins
	inFile map[string]string
	// emails maps the local part of each email address to its stand-in
	emails map[string]string
	// baseScopes caches the scope of each manifest skills glob base
	// (linkInScope)
	baseScopes map[string]baseScope
	// foreignLinks are private-store links to places that aren't the
	// agent's (store_links.go): recorded, nothing behind them collected
	foreignLinks []string
	// treeScans caches, by real path, a tree's count to the entry limit
	// (limitScan); linkPlans each skills tree's link verdicts (linkPlan)
	treeScans map[string]treeScan
	linkPlans map[string]map[string]string
	// treeRecords and linkRecords count ConfigTrees entries for trees
	// (maxConfigTrees) and for links not followed (maxLinkRecords)
	treeRecords, linkRecords int
	// targets: what the manifest says about the real path of a skills-tree
	// file reached through a link (resolved_target.go)
	targets resolvedTargets
	// sinkIDs: identities of credential-store files (hard_links.go)
	sinkIDs sinkIdentities
}

// inExcludedDir reports whether match lies under an excluded directory that
// the glob reached through a wildcard. Segments above the pattern's static
// base (a user named "build") and directories the pattern names literally
// (npm package.json globs that target .../node_modules/<pkg>/package.json)
// don't count.
func inExcludedDir(pattern, match string) bool {
	return inExcludedDirAs(pattern, match, isSkillPattern(pattern))
}

// excluded is inExcludedDir for the glob being collected: a config-derived
// tree is a skill tree whatever its directory is called.
func (c *collector) excluded(pattern, match string) bool {
	return inExcludedDirAs(pattern, match, c.configTree || isSkillPattern(pattern))
}

// inExcludedDirAs is inExcludedDir with skills given: a skill tree keeps its
// build output (dist/, build/).
func inExcludedDirAs(pattern, match string, skills bool) bool {
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
	for _, h := range homes {
		c.homes = append(c.homes, h.Path)
	}
	defer recordRespellings(&snapshot, append([]string{homedir}, c.homes...))()

	// Track scanned users
	for _, h := range homes {
		priv.ScannedUsers = append(priv.ScannedUsers, h.Username)
	}
	snapshot.Privilege = priv

	// Links from private stores to places that aren't the agent's, before
	// anything is collected: nothing behind them is
	c.markForeignStoreLinks(&snapshot, expandPaths(manifest.PrivateStores, homes))

	// Expand and collect file paths
	expandedPaths := expandPaths(manifest.FilePaths, homes)
	c.targets = newResolvedTargets(expandPaths(manifest.MetadataGlobPatterns, homes),
		append(append([]string{}, expandedPaths...), manifest.SystemPaths...),
		expandPaths(manifest.GlobPatterns, homes), c.homes)
	for _, p := range expandedPaths {
		c.collectPath(&snapshot, p, p, false, true)
		c.recordExplicitLinks(&snapshot, p)
	}

	// Expand and collect system paths (not expanded per-user)
	for _, p := range manifest.SystemPaths {
		c.collectPath(&snapshot, p, p, false, true)
		c.recordExplicitLinks(&snapshot, p)
	}

	// Expand and collect glob patterns. Whether a glob walks a skill tree
	// is read from the manifest's own pattern: a home or a variable's value
	// under some ".../skills/" made every glob one, and nothing was scrubbed.
	type glob struct {
		pattern string
		skills  bool
	}
	var expandedGlobs []glob
	for _, raw := range manifest.GlobPatterns {
		for _, p := range expandPaths([]string{raw}, homes) {
			expandedGlobs = append(expandedGlobs, glob{p, isSkillPattern(raw)})
		}
	}
	for _, g := range expandedGlobs {
		c.inSkillTree = g.skills
		c.collectGlob(&snapshot, g.pattern)
	}
	c.inSkillTree = false

	// Metadata-only globs: existence + mode, never content
	for _, pattern := range expandPaths(manifest.MetadataGlobPatterns, homes) {
		// The links that take a store folder where it leads, every hop
		// (session-state → ~/hop → elsewhere): the CLI resolves it as locally
		if base := globBase(pattern); filepath.IsAbs(base) {
			if _, err := os.Lstat(base); err == nil {
				c.recordLinkChain(&snapshot, base)
			}
		}
		matches, err := doublestar.FilepathGlob(pattern, doublestar.WithNoFollow())
		if err != nil {
			continue
		}
		for _, match := range matches {
			if inExcludedDir(pattern, match) || c.behindForeignLink(match) {
				continue
			}
			recordSymlink(snapshot.Symlinks, match)
			// …and of a link in it (session-state/abc → ~/hop → elsewhere)
			if isSymlink(match) {
				c.recordLinkChain(&snapshot, match)
			}
			if _, exists := snapshot.Files[match]; !exists {
				c.collectPath(&snapshot, match, globBase(pattern), true, false)
			}
		}
		c.followLinkedTrees(&snapshot, pattern, matches, true)
		c.followLinkedMetadata(&snapshot, pattern)
	}

	// Trees and paths agents' configs set (a workspace moved elsewhere, an
	// MCP server's command), read from the configs collected above. After the
	// metadata globs: a private store inside such a tree (sessions, memory,
	// tokens) is already recorded as metadata and stays that way.
	c.collectConfigRoots(&snapshot, manifest.ConfigRoots, homes)

	// Expand and collect directory listings. Only non-nil listings are stored:
	// a nil result means the directory doesn't exist or can't be read, and
	// inserting a key with a nil value would cause downstream consumers to
	// report the directory as "present". A directory that exists but can't be
	// listed (mode 000) still gets its mode recorded, so it is present
	// remotely the way it is locally.
	expandedDirs := expandPaths(manifest.DirectoryListings, homes)
	for _, dir := range expandedDirs {
		if c.behindForeignLink(dir) {
			continue
		}
		// One a link takes out of the home to where no skills tree is walked
		// (~/.claude/skills → /etc): not listed — its links are recorded.
		// Nor a private store's link to a place that isn't the agent's
		if c.isForeignLink(dir) {
			c.recordLinkChain(&snapshot, dir)
		} else if c.linkedOutRefused(dir) {
			c.recordLinkChain(&snapshot, dir)
		} else if listing := collectDirectory(dir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[dir] = listing
		}
		recordDirMode(&snapshot, dir)
	}

	// Collect system directory listings (not expanded per-user)
	for _, dir := range manifest.SystemDirListings {
		if c.behindForeignLink(dir) || c.isForeignLink(dir) {
			continue
		}
		if listing := collectDirectory(dir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[dir] = listing
		}
		recordDirMode(&snapshot, dir)
	}
	// Home dirs gate traversal for everything beneath them (parent-directory
	// mitigation on the TS side needs their real modes).
	for _, h := range homes {
		recordDirMode(&snapshot, h.Path)
		recordResolvedDir(&snapshot, h.Path)
	}
	recordResolvedDir(&snapshot, homedir)

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
			out := c.runManifestCommand(req, cmdPath)
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
	c.recordCollectedLinkChains(&snapshot)
	recordAncestorModes(&snapshot, c.explicit)

	// Collect filtered environment variables
	snapshot.Env = collectEnv(manifest.EnvPrefixes)
	for _, name := range manifest.EnvOriginOnly {
		if v, ok := snapshot.Env[name]; ok {
			snapshot.Env[name] = urlOriginOnly(v)
		}
	}
	for _, name := range manifest.EnvPresence {
		delete(snapshot.Env, name) // a prefix may have collected it
		if strings.TrimSpace(os.Getenv(name)) != "" {
			snapshot.Env[name] = envPresentValue
		}
	}
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

// collectGlob collects a glob's matches (content, or metadata past the
// limits), the trees its symlinks point to, names a glob can't match and
// directories it couldn't read. c.inSkillTree says whether it walks skills.
func (c *collector) collectGlob(snapshot *ProbeSnapshot, pattern string) {
	if c.inSkillTree && !c.configTree && c.linkedOutSkillBase(snapshot, pattern) {
		return
	}
	// Never descend into symlinked directories: a local readdir lists the
	// link without following it, so following here duplicated every file
	// a skill symlinks in from elsewhere. The link itself still matches.
	matches, err := doublestar.FilepathGlob(pattern, doublestar.WithNoFollow())
	if err != nil {
		return
	}
	for _, match := range matches {
		if c.excluded(pattern, match) || c.behindForeignLink(match) {
			continue
		}
		// A link is recorded (name and target, never what it points to)
		// wherever it leads: SKL-013 reports a link out of the tree from it
		recordSymlink(snapshot.Symlinks, match)
		// …and, for one into a credential store, every hop to it (names and
		// targets only): SKL-013 judges where it really leads, as locally
		if c.inSkillTree && linkIntoSink(match, sinkSet(globBase(pattern))) {
			c.recordLinkChain(snapshot, match)
		}
		// A config-derived tree's entries outside its user's home or in a
		// credential store (as named or resolved) aren't collected — except
		// a file that really is in one through a link (a skills dir linked
		// to ~/.claude lists .credentials.json): recorded as a manifest tree
		// records it, present with its mode and no content (collectFileLimit
		// omits it as sensitive)
		if c.configTree && !treeAllowed(match, c.treeHome) && !c.sinkFileByTarget(pattern, match) {
			continue
		}
		if _, exists := snapshot.Files[match]; !exists {
			c.collectPath(snapshot, match, globBase(pattern), false, false)
		}
	}
	c.followLinkedTrees(snapshot, pattern, matches, false)
	c.collectNonUTF8Names(snapshot, pattern)
	c.recordDeniedDirs(snapshot, pattern)
	if c.inSkillTree {
		c.collectUnlistableSkills(snapshot, pattern)
		if !c.configTree {
			c.collectLinkedSkillBases(snapshot, pattern)
		}
	}
}

// sinkFileByTarget: match, a glob match of a config-derived tree, is a
// regular file whose real path is in a credential store neither the glob's
// base nor match's own spelling names (resolvedIntoSink).
func (c *collector) sinkFileByTarget(pattern, match string) bool {
	if info, err := os.Stat(match); err != nil || !info.Mode().IsRegular() {
		return false
	}
	return resolvedIntoSink(match, globBase(pattern))
}

// collectFile reads a file and returns its content and mode. Content is
// omitted (Exists+Mode only, ContentOmitted set) for metadata-only requests,
// files over maxFileContentBytes, and once the snapshot's total content budget
// is spent — enough for adapters that only need presence or permissions.
func (c *collector) collectFile(path string, metadataOnly bool) FileEntry {
	return c.collectFileLimit(path, path, metadataOnly, maxFileContentBytes)
}

// globBase is the static part of a glob, before its first wildcard: the
// directory VASO asked for, below which a skill tree's own names begin.
func globBase(pattern string) string {
	base, _ := doublestar.SplitPattern(filepath.ToSlash(pattern))
	return filepath.FromSlash(base)
}

// base is the part of path VASO named (see escapesToSink).
func (c *collector) collectFileLimit(path, base string, metadataOnly bool, limit int64) FileEntry {
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
	// A manifest skills tree's file is judged by where it really is too
	// (resolved_target.go): a link can spell an agent's own files as skills
	target := ""
	if c.inSkillTree && !c.configTree {
		target = skillTarget(path)
	}
	hardSink := ""
	if !metadataOnly {
		hardSink = c.hardLinkedSink(path, base, info)
	}
	switch {
	// Not a regular file (a FIFO, a device, a link to /dev/tty) before
	// anything else: a metadata-only credential path replaced by one must not
	// look like a credential file with a mode to fix — locally it isn't one
	case !info.Mode().IsRegular():
		return omitted("special")
	case metadataOnly:
		return omitted("metadata")
	// Before size: not even the head of a file behind such a link is shipped
	case escapesToSink(path, base):
		return omitted("sensitive")
	// …or whose real path is one, through a link above base (a skills dir
	// linked to ~/.claude): judged by where the file is, not how it is spelled
	case resolvedIntoSink(path, base):
		return omitted("sensitive")
	// …or that is a credential-store file under another name: a hard link
	case hardSink != "":
		e := omitted("sensitive")
		e.HardLinkOf = hardSink
		return e
	case target != "" && c.targets.metadataOnly(target):
		return omitted("metadata")
	// In a config-derived tree: nothing behind a link out of the user's home
	// or into a credential store, and no file a name marks as a credential
	// (token, *.key, credentials.json…) unless it is a program: executable
	// and starting like one (`#!`, ELF, Mach-O, PE) — an executable bit
	// alone doesn't make an id_ed25519 anything but a key
	case c.configTree && !treeAllowed(path, c.treeHome):
		return omitted("sensitive")
	// In a manifest skills tree: nothing behind a file link into another
	// user's home or an OS directory (skill_scope.go)
	case c.skillLinkOutOfScope(base, path):
		return omitted("sensitive")
	case c.configTree && credentialFileName(path) && (info.Mode().Perm()&0o111 == 0 || !programHeader(path)):
		return omitted("metadata")
	case assetOnly:
		return omitted("asset")
	case info.Size() > limit:
		return c.withHead(omitted("size"), path, info)
	}
	if info.Size() > c.budget {
		c.truncated = true
		return c.withHead(omitted("budget"), path, info)
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
	if c.scrubbable(path) || (target != "" && c.targets.config(target)) {
		content = c.scrubSecrets(path, content)
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
func (c *collector) collectPath(snapshot *ProbeSnapshot, p, base string, metadataOnly, listDir bool) {
	if c.behindForeignLink(p) {
		return
	}
	info, err := os.Stat(p)
	if err == nil {
		recordOwner(snapshot, p, info)
	}
	if err == nil && info.IsDir() {
		snapshot.DirectoryModes[p] = int(info.Mode().Perm())
		if listDir && !escapesToSink(p, base) && !c.isForeignLink(p) {
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
	snapshot.Files[p] = c.collectFileLimit(p, base, metadataOnly, limit)
}

// recordAncestorModes stats each parent directory of every collected file and
// directory (once each) up to the filesystem root.
//
// For explicit manifest paths, the parents of where they really are too: the
// CLI judges whether a symlinked file is reachable by its real path's parents
// (markUnreachable), resolved through the links recordExplicitLinks stored.
func recordAncestorModes(snapshot *ProbeSnapshot, explicit []string) {
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
	// …and of any collected file reached through a link (a credential store a
	// metadata glob met as a symlink, or in a linked directory)
	linked := append([]string(nil), explicit...)
	for p := range snapshot.Files {
		if resolveRecordedLinks(p, snapshot.Symlinks) != p {
			linked = append(linked, p)
		}
	}
	for _, p := range linked {
		if e, ok := snapshot.Files[p]; !ok || !e.Exists {
			continue
		}
		if r := resolveRecordedLinks(p, snapshot.Symlinks); r != p {
			visit(r)
		}
		if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
			visit(r)
		}
	}
}

// recordCollectedLinkChains records the full link chain of every collected
// file whose real path differs from its own (recordLinkChain): globs record
// only a match's first hop.
func (c *collector) recordCollectedLinkChains(snapshot *ProbeSnapshot) {
	paths := make([]string, 0, len(snapshot.Files))
	for p, e := range snapshot.Files {
		if e.Exists {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if real, err := filepath.EvalSymlinks(p); err == nil && real != p {
			c.recordLinkChain(snapshot, p)
		}
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
	root, ok := literalTreeRoot(pattern)
	if !ok {
		return
	}
	rootReal, err := realPath(root)
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
		if err != nil || info.Mode()&os.ModeSymlink == 0 || c.excluded(pattern, m) || c.isForeignLink(m) || c.behindForeignLink(m) {
			continue
		}
		real, err := realPath(m)
		if err != nil || visited[real] || relatedToAny(real, roots) {
			continue
		}
		// A link into ~/.ssh, ~/.aws… is reported by SKL-013 from its target;
		// what it points to is never walked or shipped (nor locally: skill-walk.ts)
		if escapesToSink(m, globBase(pattern)) {
			continue
		}
		// A config-derived tree's links lead only where a tree may be walked,
		// nor one leading into another user's home or an OS directory. What it
		// is (a directory: a skill not scanned) is recorded, never its listing
		if (c.configTree && !treeAllowed(m, c.treeHome)) || (c.inSkillTree && !c.configTree && !c.linkInScope(globBase(pattern), m)) {
			if _, done := snapshot.DirectoryModes[m]; !done {
				recordDirMode(snapshot, m)
			}
			continue
		}
		if st, err := os.Stat(m); err != nil || !st.IsDir() {
			continue // a file link was collected (followed) by the glob itself
		}
		// A skills tree's link to a tree over the entry limit, or past the
		// total its links may hold (a plain ~/.claude/skills holding a link
		// to /opt/homebrew/Cellar), is not walked: neither collected nor
		// marked visited (another link to the same tree is recorded too)
		if c.inSkillTree && c.linkNotFollowed(snapshot, pattern, m, real) {
			continue
		}
		visited[real] = true
		escaped, ok := escapeGlobMeta(m)
		if !ok {
			continue
		}
		sub, err := doublestar.FilepathGlob(filepath.Join(escaped, "**"), doublestar.WithNoFollow())
		if err != nil {
			continue
		}
		for _, sm := range sub {
			if c.excluded(pattern, sm) || c.behindForeignLink(sm) {
				continue
			}
			recordSymlink(snapshot.Symlinks, sm)
			if c.configTree && !treeAllowed(sm, c.treeHome) {
				continue
			}
			if _, exists := snapshot.Files[sm]; !exists {
				c.collectPath(snapshot, sm, globBase(pattern), metadataOnly, false)
			}
		}
		c.followFrom(snapshot, pattern, sub, append(append([]string{}, roots...), real), visited, depth+1, metadataOnly)
	}
}

// maxLinkRecords bounds how many links not followed for size ConfigTrees
// records (src/core/snapshot-load.ts MAX_LINK_RECORDS). Past it, no
// directory link in a skills tree is followed (SkillLinksTruncated).
var maxLinkRecords = 20000

// linkNotFollowed: the directory link m (leading to real), met while walking
// a skills tree, is not followed for the size of what it leads to — over the
// entry limit, or past the total the tree's links may hold together
// (linkPlan; a link the plan gives no verdict is judged by its own count).
// Such a link is recorded in ConfigTrees ("limit" or "total"), with its mode
// (a directory: the CLI reports it not scanned, as a local walk leaves it out
// — linkCap in src/core/skill-root-scope.ts).
func (c *collector) linkNotFollowed(snapshot *ProbeSnapshot, pattern, m, real string) bool {
	if snapshot.SkillLinksTruncated {
		return true
	}
	root, ok := literalTreeRoot(pattern)
	if !ok {
		root = globBase(pattern)
	}
	home := c.treeHome
	if !c.configTree {
		home = c.homeOf(root)
	}
	if home == "" {
		// a tree in no home: judged for the probe user, as local scans do
		home, _ = os.UserHomeDir()
	}
	verdict, planned := c.linkPlan(root, home)[real]
	if !planned {
		verdict = linkFollow
		if c.limitScan(real).n > maxConfigTreeEntries {
			verdict = linkLimit
		}
	}
	if verdict == linkFollow {
		return false
	}
	if snapshot.ConfigTrees == nil {
		snapshot.ConfigTrees = make(map[string]string)
	}
	key := filepath.ToSlash(filepath.Clean(m))
	if _, done := snapshot.ConfigTrees[key]; !done {
		if c.linkRecords >= maxLinkRecords {
			snapshot.SkillLinksTruncated = true
			return true
		}
		c.linkRecords++
		snapshot.ConfigTrees[key] = verdict
	}
	if _, done := snapshot.DirectoryModes[m]; !done {
		recordDirMode(snapshot, m)
	}
	return true
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
	return runCommandScrubbed(req, augmentedPath, redactSecretValues)
}

// runCommandScrubbed is runCommand with stdout passed through scrubOut
// (stderr is always redacted).
func runCommandScrubbed(req CommandRequest, augmentedPath string, scrubOut func(string) string) CommandOutput {
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
	// A command that exits but leaves a background child holding stdout (a
	// shim's `( sleep 30 ) &`) made Wait block until that child ended, past
	// the timeout. The command leads its own process group, a timeout kills
	// the group, and the pipes are closed waitDelay after it exits.
	ownProcessGroup(cmd)
	cmd.WaitDelay = waitDelay

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
		if uid, gid, userOwned, refuse := dropCredential(info); refuse != "" {
			return CommandOutput{Stderr: fmt.Sprintf("%s %s", real, refuse), ExitCode: -1}
		} else if userOwned {
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
	killProcessGroup(cmd) // what it left running

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil {
			// Exited normally; only its leftover child held the pipes
			exitCode = cmd.ProcessState.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// A CLI can quote the files it read in its output, an error message
	// above all ("Unknown gateway '<file contents>'"): no check reads a
	// credential from a command, so none leaves the host in one
	return CommandOutput{
		Stdout:   scrubOut(stdout.String()),
		Stderr:   redactSecretValues(unwrapGutter(stderr.String())),
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
	"COOKIE": true, "SESSION": true, "JWT": true, "DSN": true, "BEARER": true,
	"HEADER": true, "HEADERS": true, "AUTHORIZATION": true, "SIGNATURE": true,
	// GH_PAT (a personal access token), DB_PWD, CLAUDE_PW, SIM_PIN
	"PAT": true, "PWD": true, "PW": true, "PIN": true,
}

// Segments that end in a credential word without a separator
// (GITHUB_ACCESSTOKEN, SLACK_BOTTOKEN, AGENT_PRIVATEKEY, OPENAI_APIKEY).
var secretEnvSuffixes = []string{"TOKEN", "TOKENS", "KEY", "KEYS", "SECRET", "PASSWORD", "PASSWD", "JWT", "DSN"}

var locationEnvSuffix = map[string]bool{"PATH": true, "DIR": true, "FILE": true, "HOME": true, "URL": true}

func isSecretEnvName(name string) bool {
	parts := strings.Split(strings.ToUpper(name), "_")
	// PWD alone is the shell's working directory
	if locationEnvSuffix[parts[len(parts)-1]] || len(parts) == 1 && parts[0] == "PWD" {
		return false
	}
	for _, p := range parts {
		if secretEnvParts[p] {
			return true
		}
		for _, s := range secretEnvSuffixes {
			if strings.HasSuffix(p, s) {
				return true
			}
		}
	}
	return false
}

// camelBoundary splits JSON keys such as apiKey or authToken into words.
var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// isSecretJSONKey applies the env-name rule to a JSON key (apiKey,
// Authorization, x-api-key, headers).
func isSecretJSONKey(key string) bool {
	k := camelBoundary.ReplaceAllString(key, "${1}_${2}")
	return isSecretEnvName(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(k))
}

// urlUserinfo matches the user:password@ part of a URL: up to the last @
// before the host (WHATWG; a password may hold an @). It never runs past
// what ends a URL in JSON or XML text (`"https://x" … "a@b"` is no userinfo).
var urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s"'<>,{}]+@`)

// redactURLUserinfo keeps a URL's scheme and host (checks judge http:// and
// the endpoint) but never its credentials: proxy://user:pass@host.
func redactURLUserinfo(s string) string {
	return urlUserinfo.ReplaceAllString(s, "${1}"+redactedEnvValue+"@")
}

// tokenShaped matches the credential formats VASO's checks recognise (API_KEY_PATTERNS
// and EXTRA_TOKEN_PATTERNS, TestTokenShapedCoversEveryFormat), wherever
// they stand in a value: a token in a variable whose name looks harmless
// (OPENAI_ORG=sk-proj-…, LYRIE_TELEGRAM_BOT=123456:…) must not ship either.
// RE2 is linear, so no input can make this slow.
var tokenShaped = regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-|ant-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_-]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|\bgsk_[A-Za-z0-9]{20,}|\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}|\bhf_[A-Za-z0-9]{20,}|\bxai-[A-Za-z0-9]{32,}|A(?:KIA|SIA)[0-9A-Z]{16,}|\bdevin-[A-Za-z0-9$._-]{60,}|\bcog_[A-Za-z0-9]{16,}|\bapk_(?:user_)?[A-Za-z0-9]{16,}|\bnvapi-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{20,}|\b[0-9]{6,12}:[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*|` +
	// formats the checks don't name, never shipped either: Stripe, SendGrid,
	// DigitalOcean, Shopify, Linear, Notion, Perplexity
	`\b[sr]k_live_[A-Za-z0-9]{20,}|\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|\bdop_v1_[a-f0-9]{64}|\bshpat_[a-fA-F0-9]{32}|\blin_api_[A-Za-z0-9]{32,}|\bntn_[A-Za-z0-9]{32,}|\bpplx-[A-Za-z0-9]{32,}|` +
	// Vault tokens (hvs./hvb./hvr., legacy s./r.);
	// npm, PyPI, Figma, Docker Hub, Google OAuth access tokens
	`\bhv[sbr]\.[A-Za-z0-9_-]{24,}|\b[sr]\.[A-Za-z0-9]{24}\b|\bnpm_[A-Za-z0-9]{36,}|\bpypi-AgE[A-Za-z0-9_-]{50,}|\bfigd_[A-Za-z0-9_-]{40,}|\bdckr_pat_[A-Za-z0-9_-]{24,}|\bya29\.[A-Za-z0-9_-]{40,})`)

// gutterWrap is a continuation line of a Rust CLI error report (miette, as
// openshell prints it): the report is wrapped to the terminal width anywhere,
// even inside a token, and each continuation starts with a "│" gutter.
var gutterWrap = regexp.MustCompile(`\n[ \t]*│ ?`)

// unwrapGutter joins such continuations, so a token the report broke across
// lines is one token again for redactSecretValues.
func unwrapGutter(s string) string {
	return gutterWrap.ReplaceAllString(s, "")
}

// urlParam matches one name=value pair in a URL's query or fragment. The
// value stops where the URL does inside JSON or XML (`…token=x</string>`).
var urlParam = regexp.MustCompile(`([?&#;])([^=&#;\s"'<>]+)=([^&#;\s"'<>]*)`)

// redactSecretValues keeps a value's structure (scheme, host, parameter names)
// but none of its credentials: user:password@, credential-named URL parameters
// (?api_key=, &token=), secret URL path segments and token-shaped text anywhere.
func redactSecretValues(s string) string {
	s = redactURLUserinfo(s)
	// a URL whose path is the credential (Zapier MCP, webhooks, random tokens)
	s = replaceURLPathSecrets(s, func(string) string { return redactedEnvValue })
	// …/mcp#<token>: a token that is the whole fragment
	s = replaceURLFragmentTokens(s, func(string) string { return redactedEnvValue })
	s = urlParam.ReplaceAllStringFunc(s, func(m string) string {
		g := urlParam.FindStringSubmatch(m)
		if urlSecretParam(g[2]) && g[3] != "" {
			return g[1] + g[2] + "=" + redactedEnvValue
		}
		return m
	})
	// what the shared argv rules call a credential, in printed JSON args
	// arrays and on command lines (mysql -p, sshpass -p, redis-cli -a, -k):
	// redacted however plain the value is
	s = redactArgvArrays(s, redactedEnvValue)
	s = onSecretLines(s, argvHints, func(line string) string {
		return commandCredentials(line, func(string) string { return redactedEnvValue })
	})
	// --api-key X, --token=X (HERMES_EXTRA_ARGS, a command line in output):
	// as in files, judged by the value
	s = flagCredentials(s, func(v string) string {
		if !worthDisguising(v) && !plainCredential(v) {
			return v
		}
		return redactedEnvValue
	})
	// Authorization: Bearer <opaque>, TOKEN=…, "apiKey": "…"
	s = onSecretLines(s, secretHints, func(line string) string {
		return inlineSecrets(line, false, func(key, value string) (string, bool) {
			scheme := authSchemePrefix.FindString(value)
			if core := value[len(scheme):]; !worthDisguising(core) && !(strongCredentialKey(key) && (passphraseLike(core) || shortSecret(core))) {
				return "", false
			}
			return scheme + redactedEnvValue, true
		})
	})
	return tokenShaped.ReplaceAllString(s, redactedEnvValue)
}

// redactJSONValue redacts, inside an inline JSON config
// (OPENCODE_CONFIG_CONTENT), every string under a credential-named key
// (apiKey, headers, env…) and URL credentials anywhere, keeping the structure
// checks read (permissions, MCP commands).
func redactJSONValue(v interface{}, secret bool) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			t[k] = redactJSONValue(val, secret || isSecretJSONKey(k))
		}
		return t
	case []interface{}:
		// an argv: the shared argv rules ("--api-key", "<value>"; "mysql",
		// "-p…"), the rest judged one by one
		var argv []string
		index := map[int]int{}
		for i, val := range t {
			if str, ok := val.(string); ok {
				index[len(argv)] = i
				argv = append(argv, str)
			}
		}
		hit := map[int][2]int{}
		for _, h := range judgeArgv(argv) {
			hit[index[h.tok]] = [2]int{h.from, h.to}
		}
		for i, val := range t {
			if sp, ok := hit[i]; ok {
				str := val.(string)
				t[i] = str[:sp[0]] + redactedEnvValue + str[sp[1]:]
				continue
			}
			t[i] = redactJSONValue(val, secret)
		}
		return t
	case string:
		if secret {
			return redactedEnvValue
		}
		return redactSecretValues(t)
	}
	return v
}

// redactEnvValue is what the snapshot keeps of a collected variable.
func redactEnvValue(key, val string) string {
	if isSecretEnvName(key) {
		return redactedEnvValue
	}
	trimmed := strings.TrimSpace(val)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var parsed interface{}
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			// JSONC or broken JSON: can't redact inside it, so not at all
			return redactedEnvValue
		}
		if out, err := json.Marshal(redactJSONValue(parsed, false)); err == nil {
			return string(out)
		}
		return redactedEnvValue
	}
	return redactSecretValues(val)
}

// urlParts splits a scheme://authority URL into authority-and-before, path,
// query and fragment (WHATWG-style: the authority ends at /, ? or #, and at
// \ too — for http(s) URLs a backslash is a path separator).
var urlParts = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://[^/\\?#]*)([^?#]*)(\?[^#]*)?(#.*)?$`)

// urlOriginOnly keeps a URL's scheme, host and port, and replaces a path
// other than "/", a query and a fragment with placeholders — so a check still
// sees that they were there (an app may reject a proxy URL with a path) but
// never what they held. A value that isn't a scheme://host URL is kept as is.
func urlOriginOnly(v string) string {
	trimmed := strings.TrimSpace(v)
	m := urlParts.FindStringSubmatch(trimmed)
	if m == nil {
		return v
	}
	out := m[1]
	if m[2] != "" && m[2] != "/" {
		out += "/" + redactedEnvValue
	} else {
		out += m[2]
	}
	if len(m[3]) > 1 {
		out += "?" + redactedEnvValue
	} else {
		out += m[3]
	}
	if len(m[4]) > 1 {
		out += "#" + redactedEnvValue
	} else {
		out += m[4]
	}
	return out
}

// redactedEnvValue replaces the value of a credential-bearing variable.
const redactedEnvValue = "[redacted]"

// envPresentValue stands for a set envPresence variable (ENV_PRESENT_VALUE in
// src/core/snapshot-types.ts).
const envPresentValue = "set"

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
				result[key] = redactEnvValue(key, val)
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
	root, ok := literalTreeRoot(pattern)
	if !ok || root == "" {
		return
	}
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
				c.collectPath(snapshot, p, root, false, false)
			}
		}
	}
}

// collectNonUTF8Names collects what a `<root>/**` glob skips: the glob never
// enters a directory whose name is not valid UTF-8 (Linux names are bytes),
// so a skill dir named `\xfe` hid its SKILL.md from remote scans while a local
// walk read it. Such paths are walked here, without following links, and keyed
// as the JSON encoder writes them (invalid bytes become U+FFFD), which is how
// the CLI lists them locally. macOS and Windows reject such names.
func (c *collector) collectNonUTF8Names(snapshot *ProbeSnapshot, pattern string) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" || !strings.HasSuffix(filepath.ToSlash(pattern), "/**") {
		return
	}
	root, ok := literalTreeRoot(pattern)
	if !ok {
		return
	}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == root {
			return nil
		}
		if d.IsDir() && c.excluded(pattern, filepath.Join(p, "x")) {
			return filepath.SkipDir
		}
		rel := strings.TrimPrefix(p, root)
		if utf8.ValidString(rel) || c.excluded(pattern, p) {
			return nil
		}
		recordSymlink(snapshot.Symlinks, p)
		if _, exists := snapshot.Files[p]; !exists {
			c.collectPath(snapshot, p, root, false, false)
		}
		return nil
	})
}

// maxDeniedWalkDirs bounds how many directories recordDeniedDirs lists per glob.
const maxDeniedWalkDirs = 10000

// recordDeniedDirs records the directories a glob could not read. The glob
// ignores EACCES, so an unreadable `~/.codex/rules` (`*.rules`) or
// `~/.copilot/instructions/a` (`**/*.instructions.md`) looked empty remotely
// while a local scan reported it. Each directory the pattern would list is
// visited the way the glob visits it (symlinks under a wildcard not followed,
// wildcard-reached vendor dirs skipped); a denied one gets its mode, which the
// snapshot answers with EACCES as a local readdir does. A `<root>/**` pattern
// needs none of this: `**` matches directories, so they are collected as such.
func (c *collector) recordDeniedDirs(snapshot *ProbeSnapshot, pattern string) {
	slash := filepath.ToSlash(pattern)
	if strings.HasSuffix(slash, "/**") {
		return
	}
	base, rest := doublestar.SplitPattern(slash)
	if base == "" || rest == "" {
		return
	}
	segs := strings.Split(rest, "/")
	visited := 0
	var walk func(dir string, i int)
	walk = func(dir string, i int) {
		if visited++; visited > maxDeniedWalkDirs {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsPermission(err) {
				recordDeniedDir(snapshot, dir)
			}
			return
		}
		if i >= len(segs)-1 {
			return // the last segment names files
		}
		seg := segs[i]
		if !strings.ContainsAny(seg, "*?[{") {
			walk(filepath.Join(dir, seg), i+1)
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sub := filepath.Join(dir, e.Name())
			if c.excluded(pattern, filepath.Join(sub, "x")) {
				continue
			}
			if seg == "**" {
				walk(sub, i) // any depth; what follows `**` lies in the same subtree
			} else if ok, _ := doublestar.Match(seg, e.Name()); ok {
				walk(sub, i+1)
			}
		}
	}
	walk(filepath.FromSlash(base), 0)
}

// recordDeniedDir records the mode of a directory that could not be listed —
// or, when it can't even be stat'd (its parent has no search permission), of
// the nearest ancestor that can: the one that denies everything beneath it.
func recordDeniedDir(snapshot *ProbeSnapshot, dir string) {
	for d := dir; ; d = filepath.Dir(d) {
		if info, err := os.Stat(d); err == nil {
			if info.IsDir() {
				snapshot.DirectoryModes[d] = int(info.Mode().Perm())
				recordOwner(snapshot, d, info)
			}
			return
		}
		if filepath.Dir(d) == d {
			return
		}
	}
}

// headBytes is how much of an omitted skill-tree file is shipped: what the
// CLI reads to judge a format (HEAD_BYTES in src/analyzers/binary-text.ts
// and ioc-007-binary-patterns.ts). A PE stub's header sits at e_lfanew,
// which may lie past it: then the head runs to that header, up to
// maxPEOffset as IOC-007 reads it locally.
const (
	headBytes   = 4096
	maxPEOffset = 1 << 20
)

// withHead adds the first headBytes of a regular skill-tree file to an
// omitted entry. Read on the opened file, non-blocking, so a FIFO swapped in
// after Stat can't block the probe.
func (c *collector) withHead(e FileEntry, path string, info os.FileInfo) FileEntry {
	if !c.inSkillTree || !info.Mode().IsRegular() {
		return e
	}
	f, err := openForRead(path)
	if err != nil {
		return e
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return e
	}
	// charged to the content budget like content: when it is spent, no
	// head (a tree of sparse executables must not outgrow the snapshot)
	if c.budget < int64(base64.StdEncoding.EncodedLen(headBytes)) {
		c.truncated = true
		return e
	}
	buf := make([]byte, headBytes)
	n, _ := io.ReadFull(f, buf)
	if n >= 0x40 && buf[0] == 'M' && buf[1] == 'Z' {
		// up to the PE header only when one is there: an MZ-led script has
		// no reason to ship more than 4 KiB
		pe := int(binary.LittleEndian.Uint32(buf[0x3c:0x40]))
		sig := make([]byte, 4)
		if pe+4 > n && pe <= maxPEOffset {
			if m, _ := f.ReadAt(sig, int64(pe)); m == 4 && string(sig) == "PE\x00\x00" &&
				c.budget >= int64(base64.StdEncoding.EncodedLen(pe+4)) {
				more := make([]byte, pe+4-n)
				m, _ := f.ReadAt(more, int64(n))
				buf = append(buf[:n], more[:m]...)
				n += m
			}
		}
	}
	if n > 0 {
		e.Head = base64.StdEncoding.EncodeToString(buf[:n])
		c.budget -= jsonSize(e.Head)
	}
	return e
}

// dropCredential is who a user-owned binary runs as under root: its owner,
// with the owner's own primary group — never the file's group (a file made in
// a sticky root-owned directory, macOS /private/tmp, gets group wheel).
// userOwned is false for a root-owned binary; refuse is set when the owner
// has no account to resolve.
func dropCredential(info os.FileInfo) (uid, gid int, userOwned bool, refuse string) {
	uid, _, ok := fileOwner(info)
	if !ok || uid == 0 {
		return 0, 0, false, ""
	}
	gid, found := primaryGid(uid)
	if !found {
		return 0, 0, false, fmt.Sprintf("is owned by uid %d, which has no account to run it as", uid)
	}
	return uid, gid, true, ""
}
