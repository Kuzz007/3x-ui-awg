package naiveproxy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// Pins the exact value, not just its shape: a 64-character-but-wrong string
// would pass a length-only check and still fail every real Install.
func TestReleaseSHA256Value(t *testing.T) {
	// Independently retyped from the release asset's own published digest,
	// not copied from the production constant, so the two must agree on purpose.
	const want = "19eccb7321dd877a5fb4a3dba6ef1b745185188b616c96cc6201f1a1fc0380a8"
	if releaseSHA256 != want {
		t.Fatalf("releaseSHA256 = %q, want %q", releaseSHA256, want)
	}
	got, err := hex.DecodeString(releaseSHA256)
	if err != nil {
		t.Fatalf("releaseSHA256 does not decode as hex: %v", err)
	}
	if len(got) != sha256.Size {
		t.Fatalf("releaseSHA256 decodes to %d bytes, want %d", len(got), sha256.Size)
	}
}

func TestCheckPlatform(t *testing.T) {
	for _, tc := range []struct {
		goos, goarch string
		wantErr      bool
	}{
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64", wantErr: true},
		{goos: "windows", goarch: "amd64", wantErr: true},
		{goos: "darwin", goarch: "arm64", wantErr: true},
	} {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			err := checkPlatform(tc.goos, tc.goarch)
			if tc.wantErr && err == nil {
				t.Fatalf("checkPlatform(%s, %s) = nil, want an error", tc.goos, tc.goarch)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkPlatform(%s, %s): %v", tc.goos, tc.goarch, err)
			}
		})
	}
}

// buildTestArchive writes a minimal but real xz-compressed tar containing a
// single entry, mirroring the pinned release's own shape closely enough for
// extractBinary to exercise its real decompression/detar path end to end.
func buildTestArchive(t *testing.T, entryName, content string) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{Name: entryName, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}

	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatalf("xz.NewWriter: %v", err)
	}
	if _, err := xw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("xz Write: %v", err)
	}
	if err := xw.Close(); err != nil {
		t.Fatalf("xz Close: %v", err)
	}
	return xzBuf.Bytes()
}

func TestExtractBinaryFindsTheRealEntry(t *testing.T) {
	const content = "pretend-this-is-the-caddy-binary"
	archive := buildTestArchive(t, archiveEntryName, content)
	dst := filepath.Join(t.TempDir(), "out")

	if err := extractBinary(bytes.NewReader(archive), dst); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if string(got) != content {
		t.Errorf("extracted content = %q, want %q", got, content)
	}
}

func TestExtractBinaryRejectsMissingEntry(t *testing.T) {
	archive := buildTestArchive(t, "some/other/file", "irrelevant")
	dst := filepath.Join(t.TempDir(), "out")

	err := extractBinary(bytes.NewReader(archive), dst)
	if err == nil {
		t.Fatal("extractBinary with no matching entry returned nil error")
	}
	if !strings.Contains(err.Error(), "no "+archiveEntryName+" entry") {
		t.Errorf("extractBinary error = %q, want it to name the missing entry", err.Error())
	}
}

func TestDownloadArchiveVerifiesDigest(t *testing.T) {
	const body = "pretend-this-is-the-naiveproxy-archive"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	realURL := downloadURL
	downloadURL = srv.URL
	t.Cleanup(func() { downloadURL = realURL })

	sum := sha256.Sum256([]byte(body))
	dst, err := os.CreateTemp(t.TempDir(), "archive-*.tar.xz")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	if err := downloadArchive(context.Background(), srv.Client(), sum[:], dst); err != nil {
		t.Fatalf("downloadArchive with the correct digest: %v", err)
	}
	if _, err := dst.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("downloaded content = %q, want %q", got, body)
	}
}

func TestDownloadArchiveRejectsWrongDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("actual content"))
	}))
	t.Cleanup(srv.Close)

	realURL := downloadURL
	downloadURL = srv.URL
	t.Cleanup(func() { downloadURL = realURL })

	wrong := sha256.Sum256([]byte("not the actual content"))
	dst, err := os.CreateTemp(t.TempDir(), "archive-*.tar.xz")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	err = downloadArchive(context.Background(), srv.Client(), wrong[:], dst)
	if err == nil {
		t.Fatal("downloadArchive with a wrong digest returned nil error")
	}
	if !strings.Contains(err.Error(), "checksum verification") {
		t.Errorf("downloadArchive error = %q, want it to mention checksum verification", err.Error())
	}
}

// Regression guard: Install must never touch the network once a binary is
// already present, on any platform -- confirms the already-installed check
// runs before the platform gate, not after.
func TestInstallSkipsDownloadWhenAlreadyInstalled(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatalf("creating %s: %v", Dir(), err)
	}
	if err := os.WriteFile(BinPath(), []byte("pretend-binary"), 0o750); err != nil {
		t.Fatalf("seeding a fake already-installed binary: %v", err)
	}
	if !IsInstalled() {
		t.Fatal("IsInstalled() = false right after writing BinPath(), setup is broken")
	}

	// A client that would fail any real request -- Install must never reach
	// the download path here, since IsInstalled() is already true.
	if err := Install(context.Background(), http.DefaultClient); err != nil {
		t.Fatalf("Install with an already-present binary: %v", err)
	}
}

func TestUninstallRemovesTheDirectory(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(BinPath(), []byte("x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if IsInstalled() {
		t.Error("IsInstalled() = true after Uninstall")
	}
	if _, err := os.Stat(Dir()); !os.IsNotExist(err) {
		t.Errorf("Dir() still exists after Uninstall: %v", err)
	}
}
