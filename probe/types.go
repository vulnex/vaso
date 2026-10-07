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
type CommandForEach struct {
	From   string   `json:"from"`
	Array  string   `json:"array"`
	Fields []string `json:"fields"`
}

// ProbeSnapshot is the complete output of a probe run.
type ProbeSnapshot struct {
	Version        int                      `json:"version"`
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
