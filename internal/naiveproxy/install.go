// Package naiveproxy manages the panel's NaiveProxy sidecar: a Caddy server
// built with the klzgrad/forwardproxy plugin (HTTP/2 CONNECT tunneling,
// Chromium-network-stack-compatible), reached by clients whose ClientHello
// SNI internal/frontproxy's SNI-relay splices to it -- see
// internal/frontproxy/sni_relay.go. Unlike internal/tor (system package) or
// internal/psiphon/internal/adguard (a plain downloaded binary), the
// upstream release is a compressed tar archive, so Install extracts the
// binary from it rather than writing a downloaded stream straight to disk.
package naiveproxy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ulikunitz/xz"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
)

// releaseTag/releaseSHA256 pin one klzgrad/forwardproxy release -- verified
// against the project's own GitHub release asset digest, bumped only
// deliberately.
const (
	releaseTag    = "v2.11.2-naive"
	releaseSHA256 = "19eccb7321dd877a5fb4a3dba6ef1b745185188b616c96cc6201f1a1fc0380a8"
)

// archiveEntryName is the path inside the tar this release always uses.
const archiveEntryName = "caddy-forwardproxy-naive/caddy"

// maxArchiveBytes/maxBinaryBytes bound the compressed download and the
// decompressed binary respectively -- the real archive is ~12 MiB and the
// binary inside it ~48 MiB; these only guard against a redirect or a
// decompression bomb filling the disk.
const (
	maxArchiveBytes = 64 << 20
	maxBinaryBytes  = 256 << 20
)

// binName is the file this package writes the extracted binary to on disk.
const binName = "caddy"

// Dir is where the binary lives, following the "sidecar owns a subdirectory
// of bin/" convention Tor/AdGuard/Psiphon use.
func Dir() string { return config.GetBinFolderPath() + "/naiveproxy" }

// BinPath is the Caddy executable this package manages.
func BinPath() string { return filepath.Join(Dir(), binName) }

// IsInstalled reports whether a usable binary is present.
func IsInstalled() bool {
	info, err := os.Stat(BinPath())
	return err == nil && info.Mode().IsRegular()
}

// checkPlatform rejects anything but the one platform klzgrad/forwardproxy
// actually publishes a naive-enabled Caddy build for.
func checkPlatform(goos, goarch string) error {
	if goos == "linux" && goarch == "amd64" {
		return nil
	}
	return fmt.Errorf("NaiveProxy is only available on linux/amd64 (this host is %s/%s)", goos, goarch)
}

// downloadURL is the pinned release asset. A var, not a func returning a
// constant, purely so tests can point it at an httptest server.
var downloadURL = fmt.Sprintf(
	"https://github.com/klzgrad/forwardproxy/releases/download/%s/caddy-forwardproxy-naive.tar.xz",
	releaseTag,
)

// Install downloads the pinned Caddy+forwardproxy release and extracts its
// binary. A no-op if already installed. client comes from the caller so the
// download honors the panel's own proxy, matching adguard/psiphon's Install.
func Install(ctx context.Context, client *http.Client) error {
	if IsInstalled() {
		return nil
	}
	if err := checkPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	want, err := hex.DecodeString(releaseSHA256)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("malformed pinned checksum")
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", Dir(), err)
	}

	archive, err := os.CreateTemp(Dir(), "download-*.tar.xz")
	if err != nil {
		return fmt.Errorf("cannot create a staging file: %w", err)
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	if err := downloadArchive(ctx, client, want, archive); err != nil {
		archive.Close()
		return err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		archive.Close()
		return fmt.Errorf("cannot rewind the downloaded archive: %w", err)
	}

	staging := BinPath() + ".new"
	err = extractBinary(archive, staging)
	archive.Close()
	if err != nil {
		os.Remove(staging)
		return err
	}
	if err := os.Rename(staging, BinPath()); err != nil {
		os.Remove(staging)
		return fmt.Errorf("cannot put the Caddy binary in place: %w", err)
	}
	return nil
}

// downloadArchive streams the pinned release archive into dst, verifying
// the hashed-while-downloading digest before the caller trusts the file.
func downloadArchive(ctx context.Context, client *http.Client, want []byte, dst *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", downloadURL, resp.StatusCode)
	}

	digest := sha256.New()
	body := io.LimitReader(resp.Body, maxArchiveBytes+1)
	n, err := io.Copy(dst, io.TeeReader(body, digest))
	if err != nil {
		return fmt.Errorf("cannot write the downloaded archive: %w", err)
	}
	if n > maxArchiveBytes {
		return fmt.Errorf("NaiveProxy archive is larger than the %d MiB limit", maxArchiveBytes>>20)
	}
	if got := digest.Sum(nil); !bytes.Equal(got, want) {
		return fmt.Errorf("NaiveProxy download failed checksum verification (got %x, want %x)", got, want)
	}
	return nil
}

// extractBinary reads archiveEntryName out of the xz-compressed tar in r and
// writes it to dst. Rejects anything that isn't a plain regular file (no
// symlinks, no path escaping the expected single entry name).
func extractBinary(r io.Reader, dst string) error {
	xr, err := xz.NewReader(r)
	if err != nil {
		return fmt.Errorf("NaiveProxy archive is not valid xz: %w", err)
	}
	tr := tar.NewReader(xr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("NaiveProxy archive has no %s entry", archiveEntryName)
		}
		if err != nil {
			return fmt.Errorf("reading the NaiveProxy archive: %w", err)
		}
		if hdr.Name != archiveEntryName || hdr.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o750)
		if err != nil {
			return fmt.Errorf("cannot write %s: %w", dst, err)
		}
		n, err := io.Copy(out, io.LimitReader(tr, maxBinaryBytes+1))
		closeErr := out.Close()
		if err != nil {
			return fmt.Errorf("cannot write %s: %w", dst, err)
		}
		if closeErr != nil {
			return fmt.Errorf("cannot write %s: %w", dst, closeErr)
		}
		if n > maxBinaryBytes {
			return fmt.Errorf("NaiveProxy binary is larger than the %d MiB limit", maxBinaryBytes>>20)
		}
		return nil
	}
}

// Uninstall removes everything this package installed.
func Uninstall() error {
	if err := os.RemoveAll(Dir()); err != nil {
		return fmt.Errorf("cannot remove %s: %w", Dir(), err)
	}
	return nil
}
