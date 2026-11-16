package main

// ProbeManifest defines what data the probe should collect.
type ProbeManifest struct {
	FilePaths         []string         `json:"filePaths"`
	GlobPatterns      []string         `json:"globPatterns"`
	Commands          []CommandRequest `json:"commands"`
	DirectoryListings []string         `json:"directoryListings"`
	EnvPrefixes       []string         `json:"envPrefixes"`
	SystemPaths       []string         `json:"systemPaths,omitempty"`
	SystemDirListings []string         `json:"systemDirListings,omitempty"`
	// Globs whose matches are recorded as metadata only (exists + mode, no
	// content) — for private data where checks only need permissions, such
	// as conversation stores and session transcripts.
	MetadataGlobPatterns []string `json:"metadataGlobPatterns,omitempty"`
	// Collected variables (by exact name) whose URL value is kept only up to
	// its origin: scheme, host and port, with any path, query or fragment
	// replaced by a placeholder — for endpoint overrides where checks judge
	// the host, and the rest may carry tokens or account ids.
	EnvOriginOnly []string `json:"envOriginOnly,omitempty"`
	// Variables (by exact name) recorded only as set or not: envPresentValue
	// when non-empty after trimming, nothing otherwise — never the value
	// (OpenClaw's FLY_MACHINE_ID / FLY_APP_NAME container markers).
	EnvPresence []string `json:"envPresence,omitempty"`
	// Paths an agent's config sets (workspaces, extra skill dirs, MCP server
	// commands), read from configs the probe collects (config_roots.go).
	ConfigRoots []ConfigRootRequest `json:"configRoots,omitempty"`
	// Private store folders (Copilot's session-state/, …) whose links to a
	// place that isn't the agent's — the folder itself or one linked inside
	// it — are recorded as links only, nothing behind them (store_links.go).
	PrivateStores []string `json:"privateStores,omitempty"`
}

// CommandRequest describes a command to execute during probing.
type CommandRequest struct {
	ID      string   `json:"id"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout,omitempty"` // ms, default 5000
	// IsolateHome runs the command with HOME, XDG dirs and cwd pointed at a
	// throwaway directory (removed afterwards): agent CLIs may initialize
	// state in the user's home on any invocation, and a scan must not modify
	// what it scans.
	IsolateHome bool `json:"isolateHome,omitempty"`
	// ForEach runs the command once per item of an earlier command's JSON
	// output, substituting {field} placeholders in Args (see expandForEach).
	ForEach *CommandForEach `json:"forEach,omitempty"`
}

// CommandForEach names the earlier command (by ID) whose stdout is JSON, the
// top-level key of the array to iterate (a bare top-level array is accepted
// too), and the string fields of each item substituted for {field} in Args.
// Defaults supplies a value for a field an item omits (an OpenShell sandbox
// listed without a workspace lives in "default").
type CommandForEach struct {
	From     string            `json:"from"`
	Array    string            `json:"array"`
	Fields   []string          `json:"fields"`
	Defaults map[string]string `json:"defaults,omitempty"`
}

// ProbeSnapshot is the complete output of a probe run.
type ProbeSnapshot struct {
	Version int `json:"version"`
	// The probe build that collected this snapshot (probe ≥ 1.3.1), so the
	// CLI can say when an older probe collected less than it knows to ask for.
	ProbeVersion   string                   `json:"probeVersion,omitempty"`
	Hostname       string                   `json:"hostname"`
	Platform       string                   `json:"platform"`
	Homedir        string                   `json:"homedir"`
	Timestamp      string                   `json:"timestamp"`
	Privilege      PrivilegeInfo            `json:"privilege"`
	Files          map[string]FileEntry     `json:"files"`
	Directories    map[string][]string      `json:"directories"`
	CommandOutputs map[string]CommandOutput `json:"commandOutputs"`
	Env            map[string]string        `json:"env"`
	// Permission bits of listed directories and user homes, so remote
	// permission checks evaluate real modes instead of guessing.
	DirectoryModes map[string]int `json:"directoryModes,omitempty"`
	// True when the content budget was exhausted and later files were
	// recorded as metadata only.
	Truncated bool `json:"truncated,omitempty"`
	// Symlinks met in directory listings and glob matches (path → link
	// target), so the CLI lists them as links like a local readdir does, and
	// symlink checks (SKL-013) can evaluate targets remotely.
	Symlinks map[string]string `json:"symlinks,omitempty"`
	// Owner [uid, gid] of collected files and directories, and the host's
	// user-private groups (gid → uid), so group bits on 664 files in an
	// owner-only group are not reported as exposure.
	Owners        map[string][2]int `json:"owners,omitempty"`
	PrivateGroups map[string]int    `json:"privateGroups,omitempty"`
	// Config-derived trees (configRoots "tree"), by walk base (a path, or a
	// pattern for a wildcard base such as <dir>/workspace-*/skills): whether
	// it was collected, refused (a base no tree is walked from) or over the
	// entry limit. Only a collected tree's absence of files means "empty".
	// Also each directory link in a skills tree that was not followed for
	// size: over the entry limit ("limit") or past the links' total ("total").
	ConfigTrees map[string]string `json:"configTrees,omitempty"`
	// More links in skills trees went unfollowed for size than ConfigTrees
	// records (maxLinkRecords): after that no directory link in a skills tree
	// was followed, and an unrecorded one with nothing under it is not verified.
	SkillLinksTruncated bool `json:"skillLinksTruncated,omitempty"`
	// Where a scanned home, or a directory naming a home the other way (a
	// config's workspace spelled through a link to the home), resolves to —
	// only when that differs from its spelling. The CLI resolves either
	// spelling of a linked home with it when judging config-set skills
	// directories; the links themselves are not recorded (snapshot keys stay
	// as spelled).
	ResolvedDirs map[string]string `json:"resolvedDirs,omitempty"`
	// For a config tree's wildcard directory that lies directly in a home (a
	// workspace set in the home: `~/workspace-*/skills` beside it), which the
	// probe never lists: the names in it its wildcard segment matches, keyed
	// "<dir>/<segment>" (e.g. "/home/u/workspace-*"). The CLI tells a derived
	// `workspace-<id>` that doesn't exist from one never looked at — matching
	// only segments of its own manifest, never compiling snapshot text.
	WildcardNames map[string][]string `json:"wildcardNames,omitempty"`
}

// PrivilegeInfo describes the privilege level of the probe process.
type PrivilegeInfo struct {
	UID           int      `json:"uid"`
	Username      string   `json:"username"`
	IsRoot        bool     `json:"isRoot"`
	SudoAvailable bool     `json:"sudoAvailable"`
	Escalated     bool     `json:"escalated"`
	ScannedUsers  []string `json:"scannedUsers"`
	SkippedPaths  []string `json:"skippedPaths"`
}

// FileEntry holds the content and metadata for a collected file.
type FileEntry struct {
	Content string `json:"content"`
	Mode    int    `json:"mode"`
	Exists  bool   `json:"exists"`
	// Set when the file exists but its content was deliberately not collected
	// (over the per-file cap, over the total budget, or a metadata-only glob).
	ContentOmitted bool `json:"contentOmitted,omitempty"`
	// Why the content was omitted (probe ≥ 1.3.1): "size" (over the per-file
	// cap), "budget" (the snapshot's content budget ran out), "asset" (binary
	// asset recorded as metadata), "metadata" (a metadata-only request), or
	// "special" (not a regular file).
	Omitted string `json:"omitted,omitempty"`
	// First bytes of a skill-tree file whose content was omitted for size or
	// budget, base64 (probe ≥ 1.3.1): an executable header sits at offset 0,
	// so IOC-007 can still tell a compiled binary from data.
	Head string `json:"head,omitempty"`
	// "base64" when the file is not valid UTF-8 (binary: protobuf settings,
	// keystores…) and Content holds its bytes base64-encoded; a JSON string
	// would replace invalid sequences and lose them. Empty means UTF-8 text.
	Encoding string `json:"encoding,omitempty"`
	// Permission denied: either stat failed (under a chmod-000 directory —
	// Exists false, the file may still be there) or the file exists but
	// can't be opened (Exists true, Mode set). Never "absent" or "empty".
	Denied bool `json:"denied,omitempty"`
	// The credential-store file this one is a hard link to (probe ≥ 1.5.0;
	// omitted "sensitive"): the same file under another name, so SKL-013
	// reports it like a link into that store.
	HardLinkOf string `json:"hardLinkOf,omitempty"`
}

// CommandOutput holds the result of an executed command.
type CommandOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

// UserHome pairs a filesystem path with its owner username.
type UserHome struct {
	Path     string
	Username string
}
