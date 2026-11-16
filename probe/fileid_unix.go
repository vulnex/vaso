//go:build unix

package main

import (
	"os"
	"syscall"
)

// fileIdentity is a stat result's device, inode and link count.
func fileIdentity(info os.FileInfo) (id fileID, nlink uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, 0, false
	}
	return fileID{uint64(st.Dev), uint64(st.Ino)}, uint64(st.Nlink), true
}
