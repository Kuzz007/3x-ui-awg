//go:build !linux

package tproxy

// killStrayProcesses is a no-op off Linux -- linux/amd64 is the only
// supported deployment target for this sidecar (see checkPlatform).
func killStrayProcesses(_ string) int { return 0 }
