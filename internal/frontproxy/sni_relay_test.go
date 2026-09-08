package frontproxy

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestNewSNIRelayListenerNoTargetsReturnsInnerUnchanged pins the actual
// regression guarantee described in newSNIRelayListener's doc comment: with
// no targets configured (every install today, and every Naive-less install
// tomorrow), Manager.Start's accept path must be the literal, unwrapped
// listener -- not a wrapper that merely behaves the same, but wrapping
// removed entirely.
func TestNewSNIRelayListenerNoTargetsReturnsInnerUnchanged(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	if got := newSNIRelayListener(inner, nil); got != inner {
		t.Fatalf("newSNIRelayListener(inner, nil) = %v, want the exact same listener back", got)
	}
	if got := newSNIRelayListener(inner, map[string]string{}); got != inner {
		t.Fatalf("newSNIRelayListener(inner, {}) = %v, want the exact same listener back", got)
	}
}

// clientHelloBytes returns the raw wire bytes of one real TLS ClientHello
// for the given SNI. Generated via a genuine tls.Client handshake attempt
// against a throwaway net.Pipe() peer that never replies -- tls.Client
// writes exactly one ClientHello and then blocks waiting for a ServerHello,
// so draining the pipe's other end captures those bytes and nothing else.
// This is the simplest way to get bytes crypto/tls's own parser is
// guaranteed to accept, without hand-encoding TLS record/extension framing.
func clientHelloBytes(t *testing.T, sni string) []byte {
	t.Helper()
	readSide, writeSide := net.Pipe()
	captured := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := readSide.Read(buf)
		captured <- append([]byte(nil), buf[:n]...)
		readSide.Close()
	}()
	go func() {
		//nolint:gosec // test-only handshake against a pipe that never replies; nothing is ever verified
		_ = tls.Client(writeSide, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	}()
	select {
	case b := <-captured:
		if len(b) == 0 {
			t.Fatal("captured an empty ClientHello")
		}
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("timed out capturing a ClientHello")
		return nil
	}
}

// dialAndSendClientHello opens a real TCP connection to addr and writes one
// real ClientHello for sni onto it, then returns the raw conn for the
// caller to read a reply from directly -- no concurrent tls.Client goroutine
// left touching the conn afterward, so there's no race with the caller's
// own reads.
func dialAndSendClientHello(t *testing.T, addr, sni string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write(clientHelloBytes(t, sni)); err != nil {
		t.Fatalf("write ClientHello to %s: %v", addr, err)
	}
	return conn
}

func TestPeekClientHelloSNIExtractsSNIWithoutLosingBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	hello := clientHelloBytes(t, "naive.example.test")
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Accept never returned")
	}
	defer server.Close()

	sni, prefix := peekClientHelloSNI(server)
	if sni != "naive.example.test" {
		t.Errorf("peekClientHelloSNI sni = %q, want naive.example.test", sni)
	}
	if !bytes.Equal(prefix, hello) {
		t.Errorf("prefix (%d bytes) does not match the ClientHello actually sent (%d bytes) -- some bytes were lost or altered", len(prefix), len(hello))
	}
}

// TestPeekClientHelloSNIDiscardsTheAbortAlert is the load-bearing test for
// peekConn.Write's doc comment: without that override, aborting the
// sacrificial handshake via GetConfigForClient writes a real TLS alert
// record onto the real client's socket (confirmed by reading Go's own
// crypto/tls source, see peekConn's doc comment) -- which a real client (or,
// here, a raw read on the other end of the pipe) would see arrive
// unprompted. Confirms nothing at all reaches the client side during the
// peek.
func TestPeekClientHelloSNIDiscardsTheAbortAlert(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client := dialAndSendClientHello(t, ln.Addr().String(), "example.test")

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Accept never returned")
	}
	defer server.Close()

	peekClientHelloSNI(server) // the real function under test

	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if n > 0 {
		t.Fatalf("peekClientHelloSNI wrote %d bytes back to the client -- peekConn.Write must discard everything, got: %x", n, buf[:n])
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout (nothing ever sent), got: %v", err)
	}
}

func TestSNIRelaySplicesMatchingConnectionToBackend(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	backendGotClientHello := make(chan bool, 1)
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		n, err := c.Read(buf)
		backendGotClientHello <- err == nil && n > 0 && bytes.Contains(buf[:n], []byte("naive"))
		// Echo one byte back so the client side can confirm the relay is
		// bidirectional, not just backend-bound.
		_, _ = c.Write([]byte("R"))
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	relayLn := newSNIRelayListener(frontLn, map[string]string{
		"naive.example.test": backendLn.Addr().String(),
	})

	// relayLn.Accept must never fire for a matched connection (it's spliced
	// away entirely) -- drain it in the background so a bug that leaks a
	// matched conn through doesn't just hang the test.
	go func() {
		for {
			c, err := relayLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	client := dialAndSendClientHello(t, frontLn.Addr().String(), "naive.example.test")
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 1)
	if _, err := client.Read(reply); err != nil {
		t.Fatalf("reading the backend's echoed reply through the relay: %v", err)
	}
	if reply[0] != 'R' {
		t.Errorf("relayed reply = %q, want %q", reply, "R")
	}

	select {
	case gotSNIInPrefix := <-backendGotClientHello:
		if !gotSNIInPrefix {
			t.Error("backend's ClientHello bytes did not contain the SNI relayRaw's prefix write should have carried")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received a connection -- relayRaw did not dial it")
	}
}

// TestSNIRelayPassesThroughNonMatchingSNIUnchanged is the regression test
// for the design's core safety claim: a connection SNI relay doesn't match
// must reach the real TLS listener behind it exactly as if the peek never
// happened. A real, complete TLS handshake -- both sides, independently
// checking success -- is the strongest form of that proof: any single byte
// disturbed by the peek/replay machinery fails the handshake.
func TestSNIRelayPassesThroughNonMatchingSNIUnchanged(t *testing.T) {
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	relayLn := newSNIRelayListener(frontLn, map[string]string{
		"naive.example.test": "127.0.0.1:1", // never dialed by this test
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := relayLn.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	clientConn, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	clientErrCh := make(chan error, 1)
	go func() {
		//nolint:gosec // test cert, loopback only
		clientErrCh <- tls.Client(clientConn, &tls.Config{ServerName: "some-other-site.test", InsecureSkipVerify: true}).Handshake()
	}()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Accept never returned a connection for a non-matching SNI -- the pass-through path is broken")
	}
	defer server.Close()

	certFile, keyFile, _ := writeTestCert(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsServer.Handshake(); err != nil {
		t.Fatalf("server-side handshake over the passed-through connection failed: %v -- SNI relay's peek must have disturbed the byte stream", err)
	}
	select {
	case err := <-clientErrCh:
		if err != nil {
			t.Fatalf("client-side handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client-side handshake never completed")
	}
}

func TestSNIRelayIsCaseInsensitive(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("R"))
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	// Configured key is mixed-case; the dialed SNI below is all-lowercase.
	relayLn := newSNIRelayListener(frontLn, map[string]string{
		"Naive.Example.Test": backendLn.Addr().String(),
	})
	go func() {
		for {
			c, err := relayLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	client := dialAndSendClientHello(t, frontLn.Addr().String(), "naive.example.test")
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 1)
	if _, err := client.Read(reply); err != nil {
		t.Fatalf("reading the backend's echoed reply: %v -- a lowercase SNI must still match the mixed-case configured key", err)
	}
	if reply[0] != 'R' {
		t.Errorf("relayed reply = %q, want %q", reply, "R")
	}
}
