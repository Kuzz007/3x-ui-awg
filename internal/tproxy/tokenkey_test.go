package tproxy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsureTokenKeyCreatesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.key")

	if err := ensureTokenKey(path); err != nil {
		t.Fatalf("first ensureTokenKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != tokenKeySize {
		t.Fatalf("token key is %d bytes, want %d", info.Size(), tokenKeySize)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := ensureTokenKey(path); err != nil {
		t.Fatalf("second ensureTokenKey: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("ensureTokenKey regenerated an already-existing key -- this invalidates every live session token on an unrelated restart")
	}
}

func TestEnsureTokenKeyRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := ensureTokenKey(path); err == nil {
		t.Fatal("ensureTokenKey accepted a file that is not exactly 32 bytes")
	}
}

func TestEnsureTokenKeyNoWorldOrGroupBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS has no Unix permission bits; this fork's tproxy support is linux/amd64-only anyway")
	}
	path := filepath.Join(t.TempDir(), "token.key")
	if err := ensureTokenKey(path); err != nil {
		t.Fatalf("ensureTokenKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("token key mode = %v, tproxy-server's own reader rejects any group/other bits", info.Mode().Perm())
	}
}
