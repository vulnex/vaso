//go:build !unix

package main

import "os/exec"

var runningAsRoot = func() bool { return false }

func dropTo(cmd *exec.Cmd, uid, gid int) {}
func rootSafe(path string) bool          { return true }
