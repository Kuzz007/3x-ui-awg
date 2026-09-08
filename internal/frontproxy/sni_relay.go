package frontproxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// sniPeekTimeout bounds how long peekClientHelloSNI waits for a client to
// finish sending its ClientHello before giving up and treating the
// connection as a no-match (passed through exactly as if SNI relay did not
// exist at all). Matches the neighborhood of Manager's own
// http.Server.ReadHeaderTimeout -- both exist for the same reason: a slow or
// silent client must not be able to tie up server resources indefinitely.
const sniPeekTimeout = 4 * time.Second

// errSNIPeekDone is returned from the sacrificial handshake's
// GetConfigForClient once the ClientHello's SNI has been captured, to abort
// the handshake before it does anything else. The caller never looks at
// this error -- only at what GetConfigForClient recorded -- it exists purely
// to make the abort self-documenting rather than reading as a swallowed real
// failure.
var errSNIPeekDone = errors.New("frontproxy: sni peek complete")

// newSNIRelayListener wraps inner so that, for a ClientHello whose SNI
// matches a key in targets (case-insensitively; values are loopback
// addresses like "127.0.0.1:11800"), the raw, still-encrypted bytes are
// spliced straight to that backend instead of being handed to this
// package's own TLS termination. Every other connection -- no match, no
// SNI, or not TLS at all -- is returned to the caller completely unchanged,
// with any bytes peekClientHelloSNI already consumed transparently replayed
// first, so it reaches the caller identical to a raw Accept() result.
//
// When targets is empty this returns inner unchanged: the peek/relay
// machinery below never runs at all for an install that hasn't configured
// any foreign backend, which is the common case for every existing install
// today. This is the actual regression guarantee, not just the effect of
// an empty map -- callers should rely on this rather than passing an
// always-non-nil-but-sometimes-empty map through unconditionally.
func newSNIRelayListener(inner net.Listener, targets map[string]string) net.Listener {
	if len(targets) == 0 {
		return inner
	}
	lower := make(map[string]string, len(targets))
	for sni, backend := range targets {
		lower[strings.ToLower(sni)] = backend
	}
	l := &sniRelayListener{Listener: inner, targets: lower, out: make(chan net.Conn)}
	go l.acceptLoop()
	return l
}

// sniRelayListener embeds net.Listener so Close/Addr promote unchanged;
// only Accept is overridden.
type sniRelayListener struct {
	net.Listener
	targets map[string]string
	out     chan net.Conn
	// closeErr is written exactly once, before out is closed -- Go's memory
	// model guarantees that write is visible to any goroutine that observes
	// the close via a channel receive, so Accept can read it unguarded.
	closeErr error
}

// acceptLoop pulls raw connections off the real listener as fast as it can
// and hands each to its own goroutine immediately. This is the crux of why
// a slow or hostile peek on one connection can never delay any other one:
// nothing here blocks waiting for a peek to finish, only handle (below)
// does, and each connection gets its own instance of it.
func (l *sniRelayListener) acceptLoop() {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			l.closeErr = err
			close(l.out)
			return
		}
		go l.handle(raw)
	}
}

// handle decides one connection's fate and, for the common no-match case,
// is the only thing standing between the raw Accept() result and this
// listener's own Accept() -- so what it hands to l.out for that case must
// be indistinguishable from raw itself, sni-peek bytes and all.
func (l *sniRelayListener) handle(raw net.Conn) {
	sni, prefix := peekClientHelloSNI(raw)
	if sni != "" {
		if backend, ok := l.targets[sni]; ok {
			logger.Infof("frontproxy: sni relay: %q -> %s", sni, backend)
			relayRaw(raw, prefix, backend)
			return
		}
	}
	l.out <- &replayConn{Conn: raw, prefix: bytes.NewReader(prefix)}
}

// Accept satisfies net.Listener. A repeated call after the underlying
// listener has closed keeps returning the same terminal error, matching
// the contract every other net.Listener.Accept honors.
func (l *sniRelayListener) Accept() (net.Conn, error) {
	c, ok := <-l.out
	if !ok {
		return nil, l.closeErr
	}
	return c, nil
}

// peekConn wraps a net.Conn for the sole duration of the sacrificial
// handshake in peekClientHelloSNI: every byte actually Read is mirrored
// into buf for later replay, and every Write is silently discarded.
//
// The discard is not a simplification, it's load-bearing: reading Go's own
// crypto/tls source (handshake_server.go's readClientHello) confirms that
// when GetConfigForClient returns an error, the server sends a real
// alertInternalError record to the peer *before* returning that error --
// confirmed synchronous, via conn.Write, not queued or buffered anywhere
// else (conn.go's writeRecordLocked). Without this override, every single
// peek -- match or not, including every ordinary REALITY-rejected
// connection once any SNI relay target is configured at all -- would leak a
// stray TLS alert onto the real client socket, ahead of the real handshake
// or relay that follows. Nothing of value is ever supposed to reach the
// peer during this throwaway handshake, so discarding writes here is safe
// by construction, not just convenient.
type peekConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *peekConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

func (c *peekConn) Write(p []byte) (int, error) { return len(p), nil }

// replayConn wraps a net.Conn whose opening bytes were already consumed
// (by peekClientHelloSNI, via peekConn) so a fresh consumer -- this
// package's own tls.NewListener wrapping, next in line -- sees exactly the
// byte stream a plain, unwrapped Accept() would have handed it: prefix
// first, then whatever the live connection still has to give.
type replayConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

// peekClientHelloSNI extracts the SNI from raw's opening ClientHello without
// consuming it from the connection's real byte stream: prefix is every byte
// this consumed, for a caller to replay before reading from raw itself.
// sni is "" for anything that isn't a valid, complete-within-sniPeekTimeout
// TLS ClientHello -- a plain HTTP request, a port scanner's empty probe, or
// a client too slow to finish sending it all read the same way here: no
// SNI, so no relay target can ever match, so the caller's normal path
// handles it exactly as if this function did not exist.
//
// Deliberately built on crypto/tls's own ClientHello parsing (via a
// sacrificial tls.Server handshake aborted from GetConfigForClient) rather
// than a hand-rolled TLS record parser: this is new, unproven code sitting
// in front of every connection to this package's listener, and reusing the
// stdlib's own battle-tested parser is strictly less new code to get wrong
// than reimplementing TLS record/extension framing by hand.
func peekClientHelloSNI(raw net.Conn) (sni string, prefix []byte) {
	_ = raw.SetReadDeadline(time.Now().Add(sniPeekTimeout))
	defer func() { _ = raw.SetReadDeadline(time.Time{}) }()

	pc := &peekConn{Conn: raw}
	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errSNIPeekDone
		},
	}
	_ = tls.Server(pc, cfg).Handshake()
	return sni, pc.buf.Bytes()
}

// relayRaw splices raw to backend: prefix (the ClientHello bytes
// peekClientHelloSNI already consumed from raw) is written to backend
// first, since backend needs the same opening bytes a direct Accept()
// would have given it, then both directions are piped until either side
// closes or errors. Blocks until the relay ends; call from its own
// goroutine, same as handle already does.
func relayRaw(raw net.Conn, prefix []byte, backendAddr string) {
	defer raw.Close()

	backend, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		logger.Warningf("frontproxy: sni relay: dial %s: %v", backendAddr, err)
		return
	}
	defer backend.Close()

	if len(prefix) > 0 {
		if _, err := backend.Write(prefix); err != nil {
			logger.Warningf("frontproxy: sni relay: write ClientHello prefix to %s: %v", backendAddr, err)
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, raw); done <- struct{}{} }()
	go func() { _, _ = io.Copy(raw, backend); done <- struct{}{} }()
	<-done
}
