package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

const defaultCommandTimeout = 5000 // ms

// Files larger than this are stat'd but their content is not embedded in the
// snapshot. This protects against filePath/glob entries that incidentally
// resolve to executables or large data files — without it, a single ~100 MB
// CLI binary in ~/.claude/local/claude would balloon the JSON snapshot past
// V8's ~512 MB max-string limit on the consuming Node side.
const maxFileContentBytes = 1 << 20 // 1 MiB

// Common per-user bin dirs that hold CLIs we care about. Non-interactive SSH
// sessions inherit a minimal PATH that excludes these, so we prepend them
// before running version/which probes.
var userBinDirs = []string{
	".local/bin",
	".bun/bin",
	".cargo/bin",
	".npm-global/bin",
	".volta/bin",
	".nvm/current/bin",
	".claude/local",
	"bin",
}

// buildAugmentedPath prepends each home's user bin dirs to PATH (current-user
// home first), so commands like `claude --version` resolve under non-interactive
// SSH where rc-file PATH additions don't apply.
func buildAugmentedPath(homes []UserHome, basePath string) string {
	var prefix []string
	for _, h := range homes {
		for _, d := range userBinDirs {
			prefix = append(prefix, filepath.Join(h.Path, d))
		}
	}
	if basePath == "" {
		return strings.Join(prefix, string(os.PathListSeparator))
	}
	return strings.Join(prefix, string(os.PathListSeparator)) + string(os.PathListSeparator) + basePath
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
		Hostname:       hostname,
		Platform:       runtime.GOOS,
		Homedir:        homedir,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Privilege:      priv,
		Files:          make(map[string]FileEntry),
		Directories:    make(map[string][]string),
		CommandOutputs: make(map[string]CommandOutput),
		Env:            make(map[string]string),
	}

	// Track scanned users
	for _, h := range homes {
		priv.ScannedUsers = append(priv.ScannedUsers, h.Username)
	}
	snapshot.Privilege = priv

	// Expand and collect file paths
	expandedPaths := expandPaths(manifest.FilePaths, homes)
	for _, p := range expandedPaths {
		snapshot.Files[p] = collectFile(p)
	}

	// Expand and collect system paths (not expanded per-user)
	for _, p := range manifest.SystemPaths {
		snapshot.Files[p] = collectFile(p)
	}

	// Expand and collect glob patterns
	expandedGlobs := expandPaths(manifest.GlobPatterns, homes)
	for _, pattern := range expandedGlobs {
		matches, err := doublestar.FilepathGlob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if _, exists := snapshot.Files[match]; !exists {
				snapshot.Files[match] = collectFile(match)
			}
		}
	}

	// Expand and collect directory listings
	expandedDirs := expandPaths(manifest.DirectoryListings, homes)
	for _, dir := range expandedDirs {
		snapshot.Directories[dir] = collectDirectory(dir)
	}

	// Collect system directory listings (not expanded per-user)
	for _, dir := range manifest.SystemDirListings {
		snapshot.Directories[dir] = collectDirectory(dir)
	}

	// Run allowed commands with PATH extended to include per-user bin dirs.
	// Each output is stored under both its manifest ID (e.g. "nemoclaw-help")
	// and its natural "<cmd> <args>" key (e.g. "nemoclaw help") so the TS-side
	// snapshot lookup can resolve ambiguous shared-basename commands precisely.
	cmdPath := buildAugmentedPath(homes, os.Getenv("PATH"))
	for _, cmdReq := range manifest.Commands {
		out := runCommand(cmdReq, cmdPath)
		snapshot.CommandOutputs[cmdReq.ID] = out
		naturalKey := strings.TrimSpace(cmdReq.Cmd + " " + strings.Join(cmdReq.Args, " "))
		if naturalKey != "" && naturalKey != cmdReq.ID {
			if _, exists := snapshot.CommandOutputs[naturalKey]; !exists {
				snapshot.CommandOutputs[naturalKey] = out
			}
		}
	}

	// Collect filtered environment variables
	snapshot.Env = collectEnv(manifest.EnvPrefixes)

	return snapshot
}

// expandPaths replaces ~ with each discovered user home directory.
func expandPaths(paths []string, homes []UserHome) []string {
	var expanded []string
	for _, p := range paths {
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

// collectFile reads a file and returns its content and mode. Files exceeding
// maxFileContentBytes are stat'd only — the snapshot records Exists+Mode but
// no content, which is sufficient for adapters that just need to verify a CLI
// binary's presence without parsing it.
func collectFile(path string) FileEntry {
	info, err := os.Stat(path)
	if err != nil {
		return FileEntry{Exists: false}
	}

	mode := int(info.Mode().Perm())

	if info.Size() > maxFileContentBytes {
		return FileEntry{
			Exists: true,
			Mode:   mode,
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return FileEntry{
			Exists: true,
			Mode:   mode,
		}
	}

	return FileEntry{
		Content: string(content),
		Mode:    mode,
		Exists:  true,
	}
}

// collectDirectory lists the entries of a directory.
func collectDirectory(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	return names
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
	cmd := exec.CommandContext(ctx, resolved, req.Args...)

	if augmentedPath != "" {
		env := os.Environ()
		hasPath := false
		for i, e := range env {
			if strings.HasPrefix(e, "PATH=") {
				env[i] = "PATH=" + augmentedPath
				hasPath = true
				break
			}
		}
		if !hasPath {
			env = append(env, "PATH="+augmentedPath)
		}
		cmd.Env = env
	}

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

// collectEnv returns environment variables that match any of the given prefixes.
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
