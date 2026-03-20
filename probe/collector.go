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

	// Run allowed commands
	for _, cmdReq := range manifest.Commands {
		snapshot.CommandOutputs[cmdReq.ID] = runCommand(cmdReq)
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

// collectFile reads a file and returns its content and mode.
func collectFile(path string) FileEntry {
	info, err := os.Stat(path)
	if err != nil {
		return FileEntry{Exists: false}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return FileEntry{
			Exists: true,
			Mode:   int(info.Mode().Perm()),
		}
	}

	return FileEntry{
		Content: string(content),
		Mode:    int(info.Mode().Perm()),
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

// runCommand executes a command if it is on the allowlist.
func runCommand(req CommandRequest) CommandOutput {
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

	cmd := exec.CommandContext(ctx, req.Cmd, req.Args...)

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

// DefaultManifest returns a manifest covering common agent framework paths.
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
			// MCP configs
			"~/.config/claude-desktop/claude_desktop_config.json",
			"~/.cursor/mcp.json",
			"~/.vscode/mcp.json",
		},
		GlobPatterns: []string{
			"~/.openclaw/profiles/*.json",
			"~/.openclaw/profiles/*.yaml",
			"~/.openclaw/sub-agents/**/*.json",
			"~/.nanoclaw/profiles/*.json",
			"~/.ironclaw/**/*.toml",
			"~/.zeroclaw/**/*.toml",
			"~/.nemoclaw/**/*.yaml",
		},
		Commands: []CommandRequest{
			{ID: "openclaw-version", Cmd: "openclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nanoclaw-version", Cmd: "nanoclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "picoclaw-version", Cmd: "picoclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "ironclaw-version", Cmd: "ironclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nanobot-version", Cmd: "nanobot", Args: []string{"--version"}, Timeout: 5000},
			{ID: "zeroclaw-version", Cmd: "zeroclaw", Args: []string{"--version"}, Timeout: 5000},
			{ID: "nemoclaw-version", Cmd: "nemoclaw", Args: []string{"--version"}, Timeout: 5000},
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
