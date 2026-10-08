//go:build unix

package main

import (
	"os"
	"syscall"
)

// openForRead opens without blocking, so a FIFO planted where a file is
// expected can't stall the probe waiting for a writer.
func openForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
