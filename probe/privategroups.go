package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// collectPrivateGroups finds Linux user-private groups (Debian/Ubuntu UPG): a
// group named after the single local account whose primary group it is, with
// no other members. Group bits on files in such a group reach nobody but the
// owner. Mirrors parsePrivateGroups in src/core/private-groups.ts. Returns
// gid → uid; numbers only, no names leave the host.
func collectPrivateGroups() map[string]int {
	result := map[string]int{}
	if runtime.GOOS != "linux" {
		return result
	}
	passwd, err1 := os.ReadFile("/etc/passwd")
	group, err2 := os.ReadFile("/etc/group")
	if err1 != nil || err2 != nil {
		return result
	}
	return parsePrivateGroups(string(passwd), string(group))
}

type account struct {
	name string
	uid  int
}

func parsePrivateGroups(passwd, group string) map[string]int {
	primary := map[int][]account{}
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		primary[gid] = append(primary[gid], account{f[0], uid})
	}

	result := map[string]int{}
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		users := primary[gid]
		if err != nil || len(users) != 1 || users[0].name != f[0] {
			continue
		}
		private := true
		if len(f) > 3 {
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" && m != users[0].name {
					private = false
				}
			}
		}
		if private {
			result[strconv.Itoa(gid)] = users[0].uid
		}
	}
	return result
}
