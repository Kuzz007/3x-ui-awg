package naiveproxy

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestRenderCaddyfileValidatesAgainstTheRealBinary runs "caddy validate"
// against renderCaddyfile's output. Skips, not fails, without network or off linux/amd64.
func TestRenderCaddyfileValidatesAgainstTheRealBinary(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the pinned Caddy release only runs on linux/amd64")
	}
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := Install(ctx, http.DefaultClient); err != nil {
		t.Skipf("could not install the real Caddy binary (likely no network in this environment): %v", err)
	}

	inst := testInstance()
	inst.RouteThroughXray = true
	inst.XrayRoutePort = 41200
	caddyfile, err := renderCaddyfile(inst)
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(cfgPath, []byte(caddyfile), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, BinPath(), "validate", "--config", cfgPath, "--adapter", "caddyfile")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("caddy validate rejected the rendered Caddyfile: %v\n--- output ---\n%s\n--- Caddyfile ---\n%s", err, out, caddyfile)
	}
}
