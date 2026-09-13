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

// proxySecretURL/proxyMultiConfURL are Telegram's own fixed provisioning
// endpoints. Vars, not consts, so tests can point them at an httptest server.
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
// provisioning files is missing; never overwrites one already on disk.
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

// RefreshTelegramConfig re-fetches proxy-multi.conf and reports whether it
// changed; a caller must then restart every MTProxy engine (no live reload).
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
// sanity check, so an HTML error page never becomes MTProxy's routing table.
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

// writeFileAtomic writes data to a fixed "path.new" staging file, fsyncs it,
// and renames it into place -- durable across a crash, not just a clean kill.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", tmp, err)
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot write %s: %w", tmp, errors.Join(writeErr, syncErr, closeErr))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot put %s in place: %w", path, err)
	}
	return nil
}
