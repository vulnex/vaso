//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// runningAsRoot is a variable so tests can exercise the root code paths.
var runningAsRoot = func() bool { return os.Geteuid() == 0 }

// dropTo makes cmd run as uid/gid instead of root.
func dropTo(cmd *exec.Cmd, uid, gid int) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
}

// writableByOthers: a non-root owner, or group/other write without the
// sticky bit (a sticky dir lets others add files but not replace root's).
func writableByOthers(info os.FileInfo) bool {
	uid, _, ok := fileOwner(info)
	if !ok || uid != 0 {
		return true
	}
	mode := info.Mode()
	return mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0
}

// rootSafe reports whether a root process may run path: the file (links
// resolved) and every directory above it are root's and not writable by
// anyone else, so no other user can have swapped in what runs.
func rootSafe(path string) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for p := real; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err != nil || writableByOthers(info) {
			return false
		}
		if parent := filepath.Dir(p); parent == p {
			return true
		}
	}
}
