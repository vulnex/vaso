package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"syscall"
)

// DetectPrivilege gathers privilege information about the current process.
func DetectPrivilege() PrivilegeInfo {
	info := PrivilegeInfo{
		UID:          os.Getuid(),
		IsRoot:       os.Getuid() == 0,
		ScannedUsers: []string{},
		SkippedPaths: []string{},
	}

	if u, err := user.Current(); err == nil {
		info.Username = u.Username
	}

	info.SudoAvailable = checkPasswordlessSudo()

	return info
}

// checkPasswordlessSudo returns true if sudo can be invoked without a password.
func checkPasswordlessSudo() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	cmd := exec.Command("sudo", "-n", "true")
	return cmd.Run() == nil
}

// DiscoverUserHomes enumerates home directories based on current privilege.
func DiscoverUserHomes(priv PrivilegeInfo) []UserHome {
	var homes []UserHome

	// Always include the current user's home
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, UserHome{
			Path:     home,
			Username: priv.Username,
		})
	}

	// If running as root, scan all user homes
	if priv.IsRoot {
		homes = append(homes, discoverAllHomes(priv.Username)...)
	}

	return homes
}

// discoverAllHomes finds home directories for all users on the system.
func discoverAllHomes(currentUsername string) []UserHome {
	var homes []UserHome
	var baseDirs []string

	switch runtime.GOOS {
	case "darwin":
		baseDirs = []string{"/Users"}
	case "linux":
		baseDirs = []string{"/home"}
	default:
		return homes
	}

	for _, baseDir := range baseDirs {
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			// Skip the current user (already added) and system directories
			if name == currentUsername || name == "Shared" || name == ".localized" {
				continue
			}
			homePath := filepath.Join(baseDir, name)
			homes = append(homes, UserHome{
				Path:     homePath,
				Username: name,
			})
		}
	}

	// Also check /root on Linux
	if runtime.GOOS == "linux" && currentUsername != "root" {
		if info, err := os.Stat("/root"); err == nil && info.IsDir() {
			homes = append(homes, UserHome{
				Path:     "/root",
				Username: "root",
			})
		}
	}

	return homes
}

// MaybeEscalate re-executes the current process with sudo if requested
// and passwordless sudo is available.
func MaybeEscalate(escalate bool) {
	if !escalate {
		return
	}

	// Already root, no need to escalate
	if os.Getuid() == 0 {
		return
	}

	if !checkPasswordlessSudo() {
		fmt.Fprintf(os.Stderr, "Warning: --escalate requested but passwordless sudo is not available\n")
		return
	}

	// Re-exec ourselves with sudo
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not determine executable path for escalation: %v\n", err)
		return
	}

	args := append([]string{executable}, os.Args[1:]...)
	// Remove --escalate from args to prevent infinite loop
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--escalate" {
			filtered = append(filtered, arg)
		}
	}

	cmd := exec.Command("sudo", filtered...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		os.Exit(1)
	}
	os.Exit(0)
}
