package naiveproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeChildListenPort reads the port renderCaddyfile wrote into configPath's
// site address, so each fake child in a test binds its own port, not a shared one.
var caddyfileSitePort = regexp.MustCompile(`https://:(\d+)\s*\{`)

func fakeChildListenPort(configPath string) (int, bool) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0, false
	}
	m := caddyfileSitePort.FindSubmatch(data)
	if m == nil {
		return 0, false
	}
	port, err := strconv.Atoi(string(m[1]))
	return port, err == nil
}

// TestMain re-execs the test binary as a fake caddy child (NAIVE_FAKE_CHILD=1):
// records its pid, listens on its --config file's own port, blocks. Mirrors internal/mtproto.
func TestMain(m *testing.M) {
	if os.Getenv("NAIVE_FAKE_CHILD") == "1" {
		if f, err := os.OpenFile(os.Getenv("NAIVE_FAKE_PIDFILE"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
		}
		for i, arg := range os.Args {
			if arg == "--config" && i+1 < len(os.Args) {
				if port, ok := fakeChildListenPort(os.Args[i+1]); ok {
					if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
						go func() {
							for {
								c, err := ln.Accept()
								if err != nil {
									return
								}
								c.Close()
							}
						}()
					}
				}
			}
		}
		if exitFile := os.Getenv("NAIVE_FAKE_EXIT_FILE"); exitFile != "" {
			for {
				if _, err := os.Stat(exitFile); err == nil {
					os.Exit(1)
				} else if !os.IsNotExist(err) {
					os.Exit(2)
				}
				time.Sleep(time.Millisecond)
			}
		}
		select {}
	}
	os.Exit(m.Run())
}

// installFakeCaddy points BinPath() at a copy of this test binary and arms
// TestMain's fake-child mode -- no real, linux/amd64-only Caddy binary needed.
func installFakeCaddy(t *testing.T) (pidFile string) {
	t.Helper()
	binDir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}
	pidFile = filepath.Join(binDir, "caddy-pids.txt")
	t.Setenv("XUI_BIN_FOLDER", binDir)
	// BinPath() reads XUI_BIN_FOLDER, so it must be set before calling it;
	// Dir() is a subdirectory of binDir that t.TempDir() didn't create.
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatalf("create %s: %v", Dir(), err)
	}
	if err := os.WriteFile(BinPath(), payload, 0o755); err != nil {
		t.Fatalf("install fake caddy: %v", err)
	}
	t.Setenv("NAIVE_FAKE_CHILD", "1")
	t.Setenv("NAIVE_FAKE_PIDFILE", pidFile)
	return pidFile
}

func spawnCount(t *testing.T, pidFile string) int {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	return len(strings.Fields(string(data)))
}

func waitSpawnCount(t *testing.T, pidFile string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := spawnCount(t, pidFile)
		if got == want {
			return
		}
		if got > want {
			t.Fatalf("expected %d spawn(s), got %d", want, got)
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d spawn(s), still %d after timeout", want, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// freeLoopbackPort asks the OS for a port and releases it -- a tiny race
// against the fake child's own bind, same as this pattern elsewhere here.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func testInst(t *testing.T, id int, usernames ...string) Instance {
	t.Helper()
	inst := Instance{
		Id:         id,
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort(t)),
		Domain:     "decoy.example.test",
		CertFile:   "/tmp/cert.pem",
		KeyFile:    "/tmp/key.pem",
	}
	for _, u := range usernames {
		inst.Clients = append(inst.Clients, Client{Email: u + "@x", Username: u, Password: "pw-" + u})
	}
	return inst
}

func newTestManager() *Manager {
	return &Manager{procs: map[int]*managed{}}
}

func TestEnsureStartsAProcess(t *testing.T) {
	pidFile := installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1, "alice")

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	t.Cleanup(m.StopAll)
	waitSpawnCount(t, pidFile, 1)
	if !m.IsRunning(1) {
		t.Error("IsRunning(1) = false after Ensure started it")
	}
}

func TestEnsureIsNoopWhenNothingChanged(t *testing.T) {
	pidFile := installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1, "alice")

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	t.Cleanup(m.StopAll)
	waitSpawnCount(t, pidFile, 1)

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := spawnCount(t, pidFile); got != 1 {
		t.Errorf("spawn count = %d after an identical Ensure, want 1 (no restart)", got)
	}
}

func TestEnsureRestartsWhenClientsChange(t *testing.T) {
	pidFile := installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1, "alice")

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	t.Cleanup(m.StopAll)
	waitSpawnCount(t, pidFile, 1)

	inst.Clients = append(inst.Clients, Client{Email: "bob@x", Username: "bob", Password: "pw-bob"})
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	waitSpawnCount(t, pidFile, 2)
}

// A client-less instance must not run at all: an unauthenticated
// forward_proxy is a live security hole, not just an idle process.
func TestEnsureStopsWhenClientsBecomeEmpty(t *testing.T) {
	pidFile := installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1, "alice")

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	waitSpawnCount(t, pidFile, 1)

	inst.Clients = nil
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure with no clients: %v", err)
	}
	if m.IsRunning(1) {
		t.Error("IsRunning(1) = true after Ensure with zero clients")
	}
}

func TestEnsureNeverStartsAClientlessInstance(t *testing.T) {
	pidFile := installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1) // no clients

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := spawnCount(t, pidFile); got != 0 {
		t.Errorf("spawn count = %d for a client-less instance, want 0", got)
	}
}

func TestRemoveStopsTheProcess(t *testing.T) {
	installFakeCaddy(t)
	m := newTestManager()
	inst := testInst(t, 1, "alice")

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !m.IsRunning(1) {
		t.Fatal("setup: IsRunning(1) = false right after Ensure")
	}

	m.Remove(1)
	if m.IsRunning(1) {
		t.Error("IsRunning(1) = true after Remove")
	}
}

func TestReconcileStopsWhatIsNoLongerDesired(t *testing.T) {
	installFakeCaddy(t)
	m := newTestManager()
	inst1 := testInst(t, 1, "alice")
	inst2 := testInst(t, 2, "bob")

	m.Reconcile([]Instance{inst1, inst2})
	t.Cleanup(m.StopAll)
	if !m.IsRunning(1) || !m.IsRunning(2) {
		t.Fatal("setup: both instances should be running after the first Reconcile")
	}

	m.Reconcile([]Instance{inst1})
	if !m.IsRunning(1) {
		t.Error("IsRunning(1) = false after a Reconcile that still wants it")
	}
	if m.IsRunning(2) {
		t.Error("IsRunning(2) = true after a Reconcile that no longer wants it")
	}
}

func TestStopAllStopsEveryProcess(t *testing.T) {
	installFakeCaddy(t)
	m := newTestManager()
	inst1 := testInst(t, 1, "alice")
	inst2 := testInst(t, 2, "bob")
	m.Reconcile([]Instance{inst1, inst2})
	if !m.IsRunning(1) || !m.IsRunning(2) {
		t.Fatal("setup: both instances should be running")
	}

	m.StopAll()
	if m.IsRunning(1) || m.IsRunning(2) {
		t.Error("an instance is still running after StopAll")
	}
}
