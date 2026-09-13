//go:build linux

package tproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killStrayProcesses terminates orphaned processes of one binary from a
// previous run, mirroring the sibling sidecar packages' identical helper.
func killStrayProcesses(binaryPath string) int {
	base := filepath.Base(binaryPath)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return 0
	}
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		if procExeBase(pid) != base && cmdlineArgv0Base(pid) != base {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	return killed
}

func procExeBase(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return filepath.Base(exe)
}

// cmdlineArgv0Base is the fallback for when the binary has been replaced or
// /proc/<pid>/exe is unreadable.
func cmdlineArgv0Base(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	argv0 := data
	if i := strings.IndexByte(string(data), 0); i >= 0 {
		argv0 = data[:i]
	}
	if len(argv0) == 0 {
		return ""
	}
	return filepath.Base(string(argv0))
}
