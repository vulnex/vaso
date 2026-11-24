package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// maxManifestBytes bounds the manifest read (VASO's is under 1 MiB).
const maxManifestBytes = 32 << 20

// readManifest reads the manifest file only when no other local user can have
// written or swapped it: a regular file (not a link), owned by this user (or,
// in the sudo re-run, by the user sudo was called from), not world-writable,
// in a directory others can't replace it in. The manifest names the commands
// the probe runs, so one planted in a shared /tmp would run another user's
// commands as the scanning user — as root with --escalate. VASO uploads it
// into a private mktemp directory; this check is defence in depth.
func readManifest(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := manifestTrusted(info, path); err != nil {
		return nil, err
	}
	if dir, err := os.Stat(filepath.Dir(path)); err == nil {
		if dir.Mode().Perm()&0o002 != 0 && dir.Mode()&os.ModeSticky == 0 {
			return nil, fmt.Errorf("%s is in a world-writable directory", path)
		}
	}
	f, err := openForRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Replaced between the check and the open
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxManifestBytes)
	}
	return data, nil
}

// manifestTrusted: owner and mode of the manifest (unix; elsewhere the owner
// is unknown and only the mode is judged).
func manifestTrusted(info os.FileInfo, path string) error {
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s is world-writable", path)
	}
	uid, _, ok := fileOwner(info)
	if !ok {
		return nil
	}
	euid := os.Geteuid()
	if uid == euid {
		return nil
	}
	if euid == 0 {
		if sudoUID, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil && sudoUID == uid {
			return nil
		}
	}
	return fmt.Errorf("%s is owned by uid %d, not by the user running the probe", path, uid)
}
