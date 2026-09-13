package tproxy

import (
	"fmt"
	"os"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
)

// checkPlatform rejects every host but the one release.yml builds both
// binaries for -- MTProxy's CRC32 hot path is real inline x86 asm.
func checkPlatform(goos, goarch string) error {
	if goos == "linux" && goarch == "amd64" {
		return nil
	}
	return fmt.Errorf("the Telegram web proxy is only available on linux/amd64 (this host is %s/%s)", goos, goarch)
}

// dir is where every file this package writes lives, matching the
// "sidecar owns a subdirectory of bin/" convention every other one uses.
func dir() string { return config.GetBinFolderPath() + "/tproxy" }

// tproxyServerBinaryPath is the relay binary release.yml builds for every
// platform, though it only ever runs on the one checkPlatform allows.
func tproxyServerBinaryPath() string {
	return config.GetBinFolderPath() + "/tproxy-linux-amd64"
}

// mtproxyBinaryPath is the MTProxy engine binary release.yml builds amd64-only.
func mtproxyBinaryPath() string {
	return config.GetBinFolderPath() + "/mtproxy-linux-amd64"
}

// IsInstalled reports whether both binaries this package manages are
// present. Neither is downloaded at runtime -- both ship in the release tarball.
func IsInstalled() bool {
	return isRegularFile(tproxyServerBinaryPath()) && isRegularFile(mtproxyBinaryPath())
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func serverConfigPath() string   { return dir() + "/config.json" }
func profilesPath() string       { return dir() + "/profiles.json" }
func tokenKeyPath() string       { return dir() + "/token.key" }
func publicDirPath() string      { return dir() + "/htdocs" }
func proxySecretPath() string    { return dir() + "/proxy-secret" }
func proxyMultiConfPath() string { return dir() + "/proxy-multi.conf" }
