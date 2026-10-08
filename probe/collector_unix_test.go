//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCollectFileSkipsFIFOsAndDevices(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.js")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	zero := filepath.Join(dir, "zero.js")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	c := &collector{budget: 1 << 20}
	done := make(chan [2]FileEntry, 1)
	go func() { done <- [2]FileEntry{c.collectFile(fifo, false), c.collectFile(zero, false)} }()
	select {
	case got := <-done:
		for i, e := range got {
			if !e.Exists || !e.ContentOmitted || e.Content != "" {
				t.Fatalf("entry %d: want exists + content omitted, got %+v", i, e)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collectFile blocked on a FIFO or /dev/zero")
	}
}
