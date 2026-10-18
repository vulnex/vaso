//go:build unix

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// runningAsRoot is a variable so tests can exercise the root code paths.
var runningAsRoot = func() bool { return os.Geteuid() == 0 }

// dropTo makes cmd run as uid/gid instead of root.
func dropTo(cmd *exec.Cmd, uid, gid int) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}

// ownProcessGroup runs cmd as the leader of a new process group and makes a
// timeout kill the whole group, so a background child it started can't
// outlive the timeout (killProcessGroup cleans up after a normal exit).
func ownProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// killProcessGroup kills whatever is left in cmd's process group.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// writableByOthers: a non-root owner, or group/other write without the
// sticky bit (a sticky dir lets others add files but not replace root's).
// primaryGid is the primary group of the account with this uid — what the
// account's own processes run with. A binary dropped to its owner must not
// keep the FILE's group: a file created in a sticky root-owned directory
// (macOS /private/tmp) gets group wheel, which reads e.g. /etc/sudoers.
// os/user without cgo reads /etc/passwd only (no macOS directory accounts),
// so /usr/bin/id answers when it can't.
var primaryGid = func(uid int) (int, bool) {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		if g, err := strconv.Atoi(u.Gid); err == nil {
			return g, true
		}
	}
	out, err := exec.Command("/usr/bin/id", "-g", strconv.Itoa(uid)).Output()
	if err != nil {
		return 0, false
	}
	g, err := strconv.Atoi(strings.TrimSpace(string(out)))
	return g, err == nil
}

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
