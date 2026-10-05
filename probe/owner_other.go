//go:build !unix

package main

import "os"

func fileOwner(info os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
