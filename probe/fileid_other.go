//go:build !unix

package main

import "os"

func fileIdentity(info os.FileInfo) (id fileID, nlink uint64, ok bool) { return fileID{}, 0, false }
