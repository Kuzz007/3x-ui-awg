package tproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// proxySecretURL/proxyMultiConfURL are Telegram's own MTProxy provisioning
// endpoints -- not this fork's infrastructure, not user-configurable. Every
// MTProxy deployment, including upstream's own reference one, fetches these
// same two URLs the same way. Vars, not consts, purely so tests can point
// them at an httptest server.
var (
	proxySecretURL    = "https://core.telegram.org/getProxySecret"
	proxyMultiConfURL = "https://core.telegram.org/getProxyConfig"
)

// proxySecretSize is fixed by Telegram's own endpoint, matching upstream's
// reference install-mtproxy.sh's exact validation.
const proxySecretSize = 128

// minProxyMultiConfSize guards against an empty or truncated response;
// upstream's own installer uses the same 100-byte floor.
const minProxyMultiConfSize = 100

// maxTelegramConfigBytes bounds either download -- both files are small
// (128 bytes and a few KB) and neither should ever legitimately approach this.
const maxTelegramConfigBytes = 1 << 20

// EnsureTelegramConfigFiles fetches whichever of Telegram's two MTProxy
// provisioning files is missing. It never overwrites a file already on disk --
// that is RefreshTelegramConfig's job -- so a fresh install fetches both
// exactly once and every later Ensure/Reconcile is a no-op here.
func EnsureTelegramConfigFiles(ctx context.Context, client *http.Client) error {
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir(), err)
	}
	if !isRegularFile(proxySecretPath()) {
		secret, err := fetchProxySecret(ctx, client)
		if err != nil {
			return fmt.Errorf("fetching the Telegram proxy secret: %w", err)
		}
		if err := writeFileAtomic(proxySecretPath(), secret, 0o600); err != nil {
			return err
		}
	}
	if !isRegularFile(proxyMultiConfPath()) {
		conf, err := fetchProxyMultiConf(ctx, client)
		if err != nil {
			return fmt.Errorf("fetching the Telegram proxy config: %w", err)
		}
		if err := writeFileAtomic(proxyMultiConfPath(), conf, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// RefreshTelegramConfig re-fetches proxy-multi.conf and reports whether its
// content changed. Telegram's own middle-proxy list moves occasionally
// (upstream's README: "encourage you to update it once per day"); the proxy
// secret has no such guidance and, matching upstream's own refresh script, is
// never re-fetched once obtained. Callers should restart every running
// MTProxy process when this reports changed=true -- the engine reads the file
// once at startup, no signal or endpoint reloads it.
func RefreshTelegramConfig(ctx context.Context, client *http.Client) (changed bool, err error) {
	conf, err := fetchProxyMultiConf(ctx, client)
	if err != nil {
		return false, fmt.Errorf("fetching the Telegram proxy config: %w", err)
	}
	existing, err := os.ReadFile(proxyMultiConfPath())
	if err == nil && bytes.Equal(existing, conf) {
		return false, nil
	}
	if err := writeFileAtomic(proxyMultiConfPath(), conf, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func fetchProxySecret(ctx context.Context, client *http.Client) ([]byte, error) {
	body, err := fetchURL(ctx, client, proxySecretURL)
	if err != nil {
		return nil, err
	}
	if len(body) != proxySecretSize {
		return nil, fmt.Errorf("%s returned %d bytes, want exactly %d", proxySecretURL, len(body), proxySecretSize)
	}
	return body, nil
}

func fetchProxyMultiConf(ctx context.Context, client *http.Client) ([]byte, error) {
	body, err := fetchURL(ctx, client, proxyMultiConfURL)
	if err != nil {
		return nil, err
	}
	if err := validateProxyMultiConf(body); err != nil {
		return nil, fmt.Errorf("%s: %w", proxyMultiConfURL, err)
	}
	return body, nil
}

// validateProxyMultiConf mirrors upstream's own install/refresh scripts'
// sanity check on the fetched file (byte-count floor plus both expected
// directive lines) -- a network hiccup returning an HTML error page or a
// truncated body must not silently become MTProxy's live routing table.
func validateProxyMultiConf(body []byte) error {
	if len(body) < minProxyMultiConfSize {
		return fmt.Errorf("response is %d bytes, want at least %d", len(body), minProxyMultiConfSize)
	}
	if !containsLinePrefix(body, "default ") {
		return errors.New("response has no \"default \" line")
	}
	if !containsLinePrefix(body, "proxy_for ") {
		return errors.New("response has no \"proxy_for \" line")
	}
	return nil
}

func containsLinePrefix(body []byte, prefix string) bool {
	for _, line := range bytes.Split(body, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(prefix)) {
			return true
		}
	}
	return false
}

func fetchURL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTelegramConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the response body: %w", err)
	}
	if len(body) > maxTelegramConfigBytes {
		return nil, fmt.Errorf("%s returned a body larger than the %d byte limit", url, maxTelegramConfigBytes)
	}
	return body, nil
}

// writeFileAtomic writes data to a fixed "path.new" staging file and renames
// it into place, so a process killed mid-write never leaves a truncated file
// at path for the next start to trust.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("cannot write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot put %s in place: %w", path, err)
	}
	return nil
}
