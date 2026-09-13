package tproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestValidateProxyMultiConf(t *testing.T) {
	valid := strings.Repeat("# comment padding to clear the byte floor\n", 5) + "default 1.2.3.4:443\nproxy_for 1 1.2.3.4:443\n"
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid", valid, false},
		{"too short", "default 1.2.3.4:443\nproxy_for 1 1.2.3.4:443\n", true},
		{"missing default line", strings.Repeat("#\n", 60) + "proxy_for 1 1.2.3.4:443\n", true},
		{"missing proxy_for line", strings.Repeat("#\n", 60) + "default 1.2.3.4:443\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateProxyMultiConf([]byte(c.body))
			if c.wantErr != (err != nil) {
				t.Errorf("validateProxyMultiConf(%q) error = %v, wantErr %v", c.name, err, c.wantErr)
			}
		})
	}
}

// telegramTestServers points proxySecretURL/proxyMultiConfURL at local
// httptest handlers for the duration of one test, restoring both afterward.
func telegramTestServers(t *testing.T, secret []byte, conf []byte) {
	t.Helper()
	secretSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(secret)
	}))
	confSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(conf)
	}))
	t.Cleanup(func() {
		secretSrv.Close()
		confSrv.Close()
	})
	origSecret, origConf := proxySecretURL, proxyMultiConfURL
	proxySecretURL, proxyMultiConfURL = secretSrv.URL, confSrv.URL
	t.Cleanup(func() { proxySecretURL, proxyMultiConfURL = origSecret, origConf })
}

func validMultiConf() []byte {
	return []byte(strings.Repeat("# padding\n", 10) + "default 1.2.3.4:443\nproxy_for 1 1.2.3.4:443\n")
}

func TestEnsureTelegramConfigFilesFetchesOnlyMissing(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	secret := bytes.Repeat([]byte{0x11}, proxySecretSize)
	telegramTestServers(t, secret, validMultiConf())

	if err := EnsureTelegramConfigFiles(t.Context(), http.DefaultClient); err != nil {
		t.Fatalf("EnsureTelegramConfigFiles: %v", err)
	}
	got, err := os.ReadFile(proxySecretPath())
	if err != nil {
		t.Fatalf("read proxy-secret: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("proxy-secret content mismatch")
	}
	if !isRegularFile(proxyMultiConfPath()) {
		t.Error("proxy-multi.conf was not written")
	}

	// Pre-existing files must never be overwritten by Ensure -- only Refresh does that.
	if err := os.WriteFile(proxySecretPath(), []byte("do-not-touch"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := EnsureTelegramConfigFiles(t.Context(), http.DefaultClient); err != nil {
		t.Fatalf("second EnsureTelegramConfigFiles: %v", err)
	}
	got, err = os.ReadFile(proxySecretPath())
	if err != nil {
		t.Fatalf("read proxy-secret: %v", err)
	}
	if string(got) != "do-not-touch" {
		t.Error("EnsureTelegramConfigFiles overwrote an already-present file")
	}
}

func TestEnsureTelegramConfigFilesRejectsBadSecretSize(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	telegramTestServers(t, []byte("too-short"), validMultiConf())
	if err := EnsureTelegramConfigFiles(t.Context(), http.DefaultClient); err == nil {
		t.Fatal("EnsureTelegramConfigFiles accepted a proxy-secret of the wrong size")
	}
	if isRegularFile(proxySecretPath()) {
		t.Error("a rejected download must not be left on disk")
	}
}

func TestRefreshTelegramConfigReportsChange(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	first := validMultiConf()
	telegramTestServers(t, bytes.Repeat([]byte{0x11}, proxySecretSize), first)
	if err := EnsureTelegramConfigFiles(t.Context(), http.DefaultClient); err != nil {
		t.Fatalf("EnsureTelegramConfigFiles: %v", err)
	}

	changed, err := RefreshTelegramConfig(t.Context(), http.DefaultClient)
	if err != nil {
		t.Fatalf("RefreshTelegramConfig (same content): %v", err)
	}
	if changed {
		t.Error("RefreshTelegramConfig reported a change when the content is identical")
	}

	second := []byte(strings.Repeat("# padding\n", 10) + "default 5.6.7.8:443\nproxy_for 1 5.6.7.8:443\n")
	telegramTestServers(t, bytes.Repeat([]byte{0x11}, proxySecretSize), second)
	changed, err = RefreshTelegramConfig(t.Context(), http.DefaultClient)
	if err != nil {
		t.Fatalf("RefreshTelegramConfig (changed content): %v", err)
	}
	if !changed {
		t.Error("RefreshTelegramConfig did not report a real content change")
	}
	got, err := os.ReadFile(proxyMultiConfPath())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Error("RefreshTelegramConfig did not persist the new content")
	}
}
