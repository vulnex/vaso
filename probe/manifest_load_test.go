//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dt25 g9-F1: a manifest another local user could have planted or swapped
// is refused (defence in depth; VASO uploads into a private directory).
func TestReadManifestRefusesPlantableFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(good, []byte(`{"filePaths":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readManifest(good); err != nil || string(data) != `{"filePaths":[]}` {
		t.Fatalf("own 0600 manifest: %q %v", data, err)
	}

	open := filepath.Join(dir, "open.json")
	if err := os.WriteFile(open, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(open); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable manifest accepted: %v", err)
	}

	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlinked manifest accepted: %v", err)
	}

	fifoDir := t.TempDir()
	shared := filepath.Join(fifoDir, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	inShared := filepath.Join(shared, "m.json")
	if err := os.WriteFile(inShared, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(inShared); err == nil || !strings.Contains(err.Error(), "world-writable directory") {
		t.Fatalf("manifest in a world-writable, non-sticky dir accepted: %v", err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(inShared); err != nil {
		t.Fatalf("own manifest in a sticky dir (like /tmp) refused: %v", err)
	}
}
