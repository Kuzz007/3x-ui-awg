package tproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain re-execs the test binary as a fake tproxy-server or MTProxy child
// (TPROXY_FAKE_CHILD=1): records its pid, listens on whichever port its own
// role's argv shape names, blocks. Mirrors internal/naiveproxy's identical trick.
func TestMain(m *testing.M) {
	if os.Getenv("TPROXY_FAKE_CHILD") == "1" {
		runFakeChild()
		select {}
	}
	os.Exit(m.Run())
}

func runFakeChild() {
	if f, err := os.OpenFile(os.Getenv("TPROXY_FAKE_PIDFILE"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%d\n", os.Getpid())
		f.Close()
	}
	port, ok := fakeChildPort()
	if !ok {
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return
	}
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

// fakeChildPort determines which port this fake child should bind: the
// self-invocation copy installed at tproxyServerBinaryPath() is told its port
// via "-config <path>" (config.json's own "listen" field); the copy at
// mtproxyBinaryPath() is told directly via "-H <port>", matching each real
// binary's own CLI shape.
func fakeChildPort() (int, bool) {
	base := filepath.Base(os.Args[0])
	for i, arg := range os.Args {
		switch {
		case base == filepath.Base(tproxyServerBinaryPath()) && arg == "-config" && i+1 < len(os.Args):
			return portFromServerConfig(os.Args[i+1])
		case base == filepath.Base(mtproxyBinaryPath()) && arg == "-H" && i+1 < len(os.Args):
			p, err := strconv.Atoi(os.Args[i+1])
			return p, err == nil
		}
	}
	return 0, false
}

func portFromServerConfig(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var cfg struct {
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0, false
	}
	_, portStr, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(portStr)
	return p, err == nil
}

// installFakeBinaries points both binary paths at copies of this test binary
// and arms TestMain's fake-child mode -- no real linux/amd64-only binaries needed.
func installFakeBinaries(t *testing.T) (pidFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// The fake binary is a copy of this test binary's own bytes under a
		// fixed Linux-style filename (tproxyServerBinaryPath/mtproxyBinaryPath
		// are never Windows-suffixed -- this sidecar is checkPlatform-gated to
		// linux/amd64 in production). Windows' exec refuses to launch a copy
		// without a recognized extension even given an explicit full path, so
		// this technique only works on the platform the feature actually
		// targets; CI (a Linux runner) is what actually exercises it.
		t.Skip("process-spawning fake-binary tests need linux/amd64, this fork's own tproxy support target")
	}
	binDir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}
	pidFile = filepath.Join(binDir, "pids.txt")
	t.Setenv("XUI_BIN_FOLDER", binDir)
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		t.Fatalf("create %s: %v", dir(), err)
	}
	for _, path := range []string{tproxyServerBinaryPath(), mtproxyBinaryPath()} {
		if err := os.WriteFile(path, payload, 0o755); err != nil {
			t.Fatalf("install fake binary at %s: %v", path, err)
		}
	}
	t.Setenv("TPROXY_FAKE_CHILD", "1")
	t.Setenv("TPROXY_FAKE_PIDFILE", pidFile)

	origApply := applyFirewall
	applyFirewall = func(context.Context, []int) error { return nil }
	t.Cleanup(func() { applyFirewall = origApply })

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

func seedTelegramConfigFiles(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		t.Fatalf("create %s: %v", dir(), err)
	}
	if err := os.WriteFile(proxySecretPath(), make([]byte, proxySecretSize), 0o600); err != nil {
		t.Fatalf("seed proxy-secret: %v", err)
	}
	conf := []byte(strings.Repeat("# padding\n", 10) + "default 1.2.3.4:443\nproxy_for 1 1.2.3.4:443\n")
	if err := os.WriteFile(proxyMultiConfPath(), conf, 0o600); err != nil {
		t.Fatalf("seed proxy-multi.conf: %v", err)
	}
}

func newTestManager() *Manager {
	return &Manager{instances: map[int]Instance{}, mtproxies: map[int]*managedMTProxy{}}
}

func TestManagerEnsureStartsBothProcesses(t *testing.T) {
	pidFile := installFakeBinaries(t)
	seedTelegramConfigFiles(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	if err := m.Ensure("proxy.example.com", inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if got := spawnCount(t, pidFile); got != 2 {
		t.Fatalf("spawned %d processes, want 2 (one tproxy-server, one mtproxy)", got)
	}
	addr, ok := m.ServerAddr()
	if !ok {
		t.Fatal("ServerAddr not available after Ensure")
	}
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial shared relay at %s: %v", addr, err)
	}
	conn.Close()
	if !m.IsRunning(1) {
		t.Error("IsRunning(1) = false after Ensure")
	}
}

func TestManagerEnsureIsNoopWhenNothingChanged(t *testing.T) {
	pidFile := installFakeBinaries(t)
	seedTelegramConfigFiles(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	if err := m.Ensure("proxy.example.com", inst); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	before := spawnCount(t, pidFile)

	if err := m.Ensure("proxy.example.com", inst); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if after := spawnCount(t, pidFile); after != before {
		t.Errorf("spawned %d more process(es) on an unchanged Ensure, want 0 (a real restart drops every live session on that engine)", after-before)
	}
}

func TestManagerEnsureRestartsOnlyThatInboundOnSecretChange(t *testing.T) {
	pidFile := installFakeBinaries(t)
	seedTelegramConfigFiles(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst1 := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	inst2 := Instance{Id: 2, Clients: []ClientSecret{{Name: "bob", Secret: "ffeeddccbbaa99887766554433221100"}}}
	if err := m.Ensure("proxy.example.com", inst1); err != nil {
		t.Fatalf("Ensure inbound 1: %v", err)
	}
	if err := m.Ensure("proxy.example.com", inst2); err != nil {
		t.Fatalf("Ensure inbound 2: %v", err)
	}
	before := spawnCount(t, pidFile) // 2 mtproxy + 1 shared relay so far

	inst1.Clients[0].Secret = "aabbccdd00112233445566778899eeff"
	if err := m.Ensure("proxy.example.com", inst1); err != nil {
		t.Fatalf("Ensure inbound 1 (changed): %v", err)
	}

	after := spawnCount(t, pidFile)
	// inbound 1's own engine restarts (1) and the shared relay restarts because
	// the aggregate profile set changed (1) -- inbound 2's own engine must not.
	if after-before != 2 {
		t.Errorf("spawned %d process(es) after inbound 1's secret changed, want exactly 2 (its own engine + the shared relay)", after-before)
	}
	if !m.IsRunning(2) {
		t.Error("inbound 2's engine is no longer running after an unrelated inbound's secret changed")
	}
}

func TestManagerRemoveStopsEngineAndKeepsOthers(t *testing.T) {
	installFakeBinaries(t)
	seedTelegramConfigFiles(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst1 := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	inst2 := Instance{Id: 2, Clients: []ClientSecret{{Name: "bob", Secret: "ffeeddccbbaa99887766554433221100"}}}
	if err := m.Ensure("proxy.example.com", inst1); err != nil {
		t.Fatalf("Ensure inbound 1: %v", err)
	}
	if err := m.Ensure("proxy.example.com", inst2); err != nil {
		t.Fatalf("Ensure inbound 2: %v", err)
	}

	m.Remove("proxy.example.com", 1)
	if m.IsRunning(1) {
		t.Error("inbound 1 still running after Remove")
	}
	if !m.IsRunning(2) {
		t.Error("inbound 2 was stopped by removing inbound 1")
	}
	if _, ok := m.ServerAddr(); !ok {
		t.Error("shared relay stopped even though inbound 2 still has a client")
	}
}

func TestManagerRemoveLastClientStopsSharedRelay(t *testing.T) {
	installFakeBinaries(t)
	seedTelegramConfigFiles(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	if err := m.Ensure("proxy.example.com", inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	m.Remove("proxy.example.com", 1)
	if _, ok := m.ServerAddr(); ok {
		t.Error("shared relay still reports an address after the last client was removed")
	}
}

func TestManagerEnsureRejectsMissingTelegramConfig(t *testing.T) {
	installFakeBinaries(t)
	m := newTestManager()
	t.Cleanup(m.StopAll)

	inst := Instance{Id: 1, Clients: []ClientSecret{{Name: "alice", Secret: "00112233445566778899aabbccddeeff"}}}
	if err := m.Ensure("proxy.example.com", inst); err == nil {
		t.Fatal("Ensure succeeded without proxy-secret/proxy-multi.conf ever being provisioned")
	}
}
