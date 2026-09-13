package tproxy

import (
	"crypto/rand"
	"fmt"
	"os"
)

// tokenKeySize is fixed by tproxy-server's own reader (internal/config.ReadTokenKey
// upstream): a token_key_file must be exactly 32 bytes or the relay refuses to start.
const tokenKeySize = 32

// ensureTokenKey provisions the relay's persistent signing key on first use and
// leaves an existing one untouched. Regenerating it on every start would
// invalidate every in-flight bootstrap/session token the moment the process
// restarts for an unrelated reason (a client add on a different inbound), so
// this only ever writes the file when it is missing.
func ensureTokenKey(path string) error {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Size() != int64(tokenKeySize) {
			return fmt.Errorf("%s must be a regular file containing exactly %d bytes (found %d)", path, tokenKeySize, info.Size())
		}
		return nil
	case !os.IsNotExist(err):
		return err
	}

	key := make([]byte, tokenKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("cannot generate a token key: %w", err)
	}
	return writeFileAtomic(path, key, 0o600)
}
