//go:build !linux

package naiveproxy

// killStrayCaddyProcesses is a no-op off Linux -- linux/amd64 is the only
// supported deployment target for this sidecar (see checkPlatform).
func killStrayCaddyProcesses(_ string) int { return 0 }
