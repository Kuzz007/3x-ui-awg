package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/frontproxy"
)

// writeSelfSignedCert writes a throwaway cert/key pair so frontproxy's manual
// TLS mode has something to load -- this test never performs a real
// handshake, so an unverifiable self-signed pair is fine.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "web-test"},
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

// freeLoopbackPort asks the OS for a port and immediately releases it. A tiny
// race exists between the close and frontproxy's own bind, same as any test
// using this common pattern.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Regression test for the bug fixed alongside this: StopAll() used to sit
// inside stop()'s stopXray-gated block, so StopPanelOnly() (what "Restart
// Panel" actually calls) never tore the reverse proxy down, and a changed
// domain/cert/port could never take effect from the UI. This must fail
// without that fix.
func TestStopPanelOnlyStopsFrontProxy(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	certFile, keyFile := writeSelfSignedCert(t)

	opts := frontproxy.Options{
		Listen:  "127.0.0.1",
		Port:    freeLoopbackPort(t),
		Routing: frontproxy.Config{PanelBasePath: "/secret"},
		Decoy:   frontproxy.DecoyConfig{Mode: frontproxy.DecoyTemplate},
		TLS: frontproxy.TLSSettings{
			Mode:     frontproxy.CertManual,
			Domain:   "example.test",
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}
	if err := frontproxy.GetManager().Start(opts); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer frontproxy.GetManager().StopAll()

	if !frontproxy.GetManager().IsRunning() {
		t.Fatal("manager did not come up, cannot test that stop() takes it down")
	}

	s := NewServer()
	if err := s.stop(false, true); err != nil {
		t.Fatalf("stop(false, true): %v", err)
	}

	if frontproxy.GetManager().IsRunning() {
		t.Error("frontproxy manager still running after a panel-only stop -- its StopAll() must not be gated behind stopXray")
	}
}
