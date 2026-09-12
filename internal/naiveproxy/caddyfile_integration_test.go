package naiveproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// writeSelfSignedCert writes a throwaway cert/key pair -- "caddy validate"
// provisions the full config, so a placeholder path fails differently here.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "naiveproxy-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

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
	inst.CertFile, inst.KeyFile = writeSelfSignedCert(t)
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
