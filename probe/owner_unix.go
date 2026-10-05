//go:build unix

package main

import (
	"os"
	"syscall"
)

// fileOwner returns the uid and gid of a stat result.
func fileOwner(info os.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
