//go:build !unix

package main

import "os"

func openForRead(path string) (*os.File, error) { return os.Open(path) }
