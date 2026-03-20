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
}

// CommandRequest describes a command to execute during probing.
type CommandRequest struct {
	ID      string   `json:"id"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout,omitempty"` // ms, default 5000
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
	CommandOutputs map[string]CommandOutput  `json:"commandOutputs"`
	Env            map[string]string        `json:"env"`
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
