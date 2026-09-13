package tproxy

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// managedMTProxy is one tproxy inbound's running engine.
type managedMTProxy struct {
	proc        *mtproxyProcess
	clientPort  int
	statsPort   int
	fingerprint string
}

// managedServer is the one panel-wide tproxy-server process.
type managedServer struct {
	proc        *serverProcess
	listenAddr  string
	adminAddr   string
	fingerprint string
}

// Manager owns every tproxy-related process: the one shared tproxy-server
// relay and one MTProxy engine per tproxy inbound -- see the package doc
// comment in types.go for why these two have different scopes.
type Manager struct {
	mu        sync.Mutex
	instances map[int]Instance
	mtproxies map[int]*managedMTProxy
	server    *managedServer
	swept     bool
}

var (
	managerOnce sync.Once
	manager     *Manager
)

// GetManager returns the process-wide tproxy manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{instances: map[int]Instance{}, mtproxies: map[int]*managedMTProxy{}}
	})
	return manager
}

// ServerAddr returns the loopback address the shared tproxy-server relay is
// currently listening on, for a caller (internal/frontproxy's own wiring) to
// reverse-proxy a bridge-authenticated request to. ok is false until at least
// one tproxy inbound has an active client.
func (m *Manager) ServerAddr() (addr string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == nil || !m.server.proc.IsRunning() {
		return "", false
	}
	return m.server.listenAddr, true
}

func (m *Manager) sweepOrphansLocked() {
	if m.swept {
		return
	}
	m.swept = true
	killed := killStrayProcesses(tproxyServerBinaryPath()) + killStrayProcesses(mtproxyBinaryPath())
	if killed > 0 {
		logger.Warningf("tproxy: terminated %d orphaned process(es) from a previous run", killed)
	}
}

func (inst Instance) secretsFingerprint() string {
	pairs := make([]string, 0, len(inst.Clients))
	for _, c := range inst.Clients {
		pairs = append(pairs, c.Name+"="+c.Secret)
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "|")
}

// Ensure brings the MTProxy engine for one tproxy inbound, and the shared
// relay's profile set, in line with inst. hostname is the panel's public
// domain (frontproxy's own TLS domain); tproxy shares that single domain
// rather than getting its own.
func (m *Manager) Ensure(hostname string, inst Instance) error {
	if err := checkPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	m.mu.Lock()
	m.sweepOrphansLocked()
	mtproxyStarted, err := m.ensureMTProxyLocked(inst)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	serverStarted, err := m.recomputeSharedServerLocked(hostname)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if mtproxyStarted != nil {
		if err := mtproxyStarted.WaitReady(); err != nil {
			m.Remove(hostname, inst.Id)
			return fmt.Errorf("tproxy: inbound %d: %w", inst.Id, err)
		}
	}
	if serverStarted != nil {
		if err := serverStarted.WaitReady(); err != nil {
			return fmt.Errorf("tproxy: shared relay: %w", err)
		}
	}
	return nil
}

// ensureMTProxyLocked is Ensure's non-blocking half for the per-inbound
// engine; returns the freshly spawned process to await outside the lock, or
// nil when nothing new started (including the true noop case, where this
// inbound's secret set has not actually changed).
func (m *Manager) ensureMTProxyLocked(inst Instance) (*mtproxyProcess, error) {
	if len(inst.Clients) == 0 {
		m.removeMTProxyLocked(inst.Id)
		delete(m.instances, inst.Id)
		return nil, nil
	}
	if !isRegularFile(proxySecretPath()) || !isRegularFile(proxyMultiConfPath()) {
		return nil, fmt.Errorf("tproxy: Telegram's proxy-secret/proxy-multi.conf are not provisioned yet -- call EnsureTelegramConfigFiles first")
	}

	m.instances[inst.Id] = inst
	fp := inst.secretsFingerprint()
	if cur, ok := m.mtproxies[inst.Id]; ok {
		if cur.proc.IsRunning() && cur.fingerprint == fp {
			return nil, nil
		}
	}

	clientPort, statsPort, err := m.mtproxyPortsLocked(inst.Id)
	if err != nil {
		return nil, err
	}
	secrets := make([]string, 0, len(inst.Clients))
	for _, c := range inst.Clients {
		secrets = append(secrets, c.Secret)
	}
	args, err := mtproxyArgs(clientPort, statsPort, secrets)
	if err != nil {
		return nil, fmt.Errorf("tproxy: inbound %d: %w", inst.Id, err)
	}

	if cur, ok := m.mtproxies[inst.Id]; ok {
		_ = cur.proc.Stop()
	}
	proc := newMTProxyProcess(args, fmt.Sprintf("127.0.0.1:%d", clientPort), fmt.Sprintf("mtproxy inbound %d", inst.Id))
	if err := proc.Start(); err != nil {
		return nil, err
	}
	m.mtproxies[inst.Id] = &managedMTProxy{proc: proc, clientPort: clientPort, statsPort: statsPort, fingerprint: fp}
	return proc, nil
}

// mtproxyPortsLocked returns the loopback ports inbound id's engine should
// bind: the same ones already assigned when the process already exists (a
// secrets-only restart must not also force a firewall/profiles.json churn it
// does not need), freshly allocated otherwise.
func (m *Manager) mtproxyPortsLocked(id int) (clientPort, statsPort int, err error) {
	if cur, ok := m.mtproxies[id]; ok {
		return cur.clientPort, cur.statsPort, nil
	}
	clientPort, err = freeLocalPort()
	if err != nil {
		return 0, 0, err
	}
	statsPort, err = freeLocalPort()
	if err != nil {
		return 0, 0, err
	}
	return clientPort, statsPort, nil
}

func (m *Manager) removeMTProxyLocked(id int) {
	cur, ok := m.mtproxies[id]
	if !ok {
		return
	}
	_ = cur.proc.Stop()
	delete(m.mtproxies, id)
	logger.Infof("tproxy: stopped mtproxy for inbound %d", id)
}

// recomputeSharedServerLocked rebuilds the panel-wide profile set from every
// known instance and, when it actually changed, restarts the one shared
// tproxy-server process to pick it up (or stops it when no client remains
// anywhere) and reapplies the firewall table from the current port set.
// Returns the freshly (re)started process to await outside the lock, nil when
// nothing changed.
func (m *Manager) recomputeSharedServerLocked(hostname string) (*serverProcess, error) {
	specs := m.profileSpecsLocked()

	if len(specs) == 0 {
		if m.server != nil {
			_ = m.server.proc.Stop()
			m.server = nil
			logger.Info("tproxy: stopped shared relay (no clients on any inbound)")
		}
		removeFirewall(context.Background())
		return nil, nil
	}

	profilesJSON, err := renderProfiles(specs)
	if err != nil {
		return nil, err
	}
	fp := hostname + "\x00" + string(profilesJSON)

	if m.server != nil && m.server.proc.IsRunning() && m.server.fingerprint == fp {
		return nil, nil
	}

	if err := ensureFirewall(context.Background(), m.mtproxyPortsSetLocked()); err != nil {
		return nil, fmt.Errorf("tproxy: firewall: %w", err)
	}

	listenAddr, adminAddr := "", ""
	if m.server != nil {
		listenAddr, adminAddr = m.server.listenAddr, m.server.adminAddr
	} else {
		listenAddr, err = freeLocalAddr()
		if err != nil {
			return nil, err
		}
		adminAddr, err = freeLocalAddr()
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return nil, fmt.Errorf("tproxy: cannot create %s: %w", dir(), err)
	}
	if err := os.MkdirAll(publicDirPath(), 0o755); err != nil {
		return nil, fmt.Errorf("tproxy: cannot create %s: %w", publicDirPath(), err)
	}
	if err := ensurePublicPlaceholder(); err != nil {
		return nil, err
	}
	if err := ensureTokenKey(tokenKeyPath()); err != nil {
		return nil, fmt.Errorf("tproxy: token key: %w", err)
	}
	if err := os.WriteFile(profilesPath(), profilesJSON, 0o600); err != nil {
		return nil, fmt.Errorf("tproxy: cannot write %s: %w", profilesPath(), err)
	}
	cfgJSON, err := renderServerConfig(hostname, listenAddr, adminAddr)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(serverConfigPath(), cfgJSON, 0o600); err != nil {
		return nil, fmt.Errorf("tproxy: cannot write %s: %w", serverConfigPath(), err)
	}

	if m.server != nil {
		_ = m.server.proc.Stop()
	}
	proc := newServerProcess(serverConfigPath(), listenAddr)
	if err := proc.Start(); err != nil {
		return nil, err
	}
	m.server = &managedServer{proc: proc, listenAddr: listenAddr, adminAddr: adminAddr, fingerprint: fp}
	logger.Info("tproxy: started shared relay")
	return proc, nil
}

// profileSpecsLocked builds the full cross-inbound profile list from
// m.instances, resolving each client's backend from its own inbound's
// currently assigned MTProxy client port. A client whose inbound has no
// running engine yet (should not happen -- ensureMTProxyLocked always runs
// first) is skipped rather than emitting an invalid backend.
func (m *Manager) profileSpecsLocked() []profileSpec {
	var specs []profileSpec
	for id, inst := range m.instances {
		mp, ok := m.mtproxies[id]
		if !ok {
			continue
		}
		backend := fmt.Sprintf("127.0.0.1:%d", mp.clientPort)
		for _, c := range inst.Clients {
			specs = append(specs, profileSpec{Name: c.Name, Secret: c.Secret, Backend: backend})
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs
}

func (m *Manager) mtproxyPortsSetLocked() []int {
	ports := make([]int, 0, len(m.mtproxies)*2)
	for _, mp := range m.mtproxies {
		ports = append(ports, mp.clientPort, mp.statsPort)
	}
	return ports
}

func ensurePublicPlaceholder() error {
	path := publicDirPath() + "/index.html"
	if isRegularFile(path) {
		return nil
	}
	return os.WriteFile(path, []byte(placeholderIndexHTML), 0o644)
}

// Remove stops and forgets inbound id's MTProxy engine and drops its clients
// from the shared relay's profile set, stopping the relay entirely if that
// was the last client anywhere, or rewriting and restarting it with the
// remaining ones otherwise -- hostname must be the same value passed to
// Ensure/Reconcile elsewhere, needed whenever another inbound's clients
// survive this removal and the relay's config.json must stay valid for them.
func (m *Manager) Remove(hostname string, id int) {
	m.mu.Lock()
	m.removeMTProxyLocked(id)
	delete(m.instances, id)
	_, err := m.recomputeSharedServerLocked(hostname)
	m.mu.Unlock()
	if err != nil {
		logger.Warningf("tproxy: remove inbound %d: relay recompute failed: %v", id, err)
	}
}

// Reconcile drives the running set toward desired: removes engines no longer
// wanted, (re)starts the rest, spawning under the lock and awaiting readiness
// after releasing it so one slow instance cannot stall the others, then
// (re)starts the shared relay at most once for the whole batch.
func (m *Manager) Reconcile(hostname string, desired []Instance) {
	if err := checkPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		if len(desired) > 0 {
			logger.Warningf("tproxy: reconcile skipped: %v", err)
		}
		return
	}
	m.mu.Lock()
	m.sweepOrphansLocked()

	want := make(map[int]struct{}, len(desired))
	for _, inst := range desired {
		want[inst.Id] = struct{}{}
	}
	for id := range m.mtproxies {
		if _, ok := want[id]; !ok {
			m.removeMTProxyLocked(id)
			delete(m.instances, id)
		}
	}

	type pending struct {
		id   int
		proc readyWaiter
	}
	var toAwait []pending
	for _, inst := range desired {
		proc, err := m.ensureMTProxyLocked(inst)
		if err != nil {
			logger.Warningf("tproxy: reconcile failed for inbound %d: %v", inst.Id, err)
			continue
		}
		if proc != nil {
			toAwait = append(toAwait, pending{inst.Id, proc})
		}
	}

	serverProc, err := m.recomputeSharedServerLocked(hostname)
	m.mu.Unlock()
	if err != nil {
		logger.Warningf("tproxy: reconcile: shared relay recompute failed: %v", err)
	}

	for _, p := range toAwait {
		if err := p.proc.WaitReady(); err != nil {
			logger.Warningf("tproxy: inbound %d: %v", p.id, err)
		}
	}
	if serverProc != nil {
		if err := serverProc.WaitReady(); err != nil {
			logger.Warningf("tproxy: shared relay: %v", err)
		}
	}
}

// StopAll stops every managed process and drops the firewall table. Called on
// panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	for id := range m.mtproxies {
		m.removeMTProxyLocked(id)
	}
	m.instances = map[int]Instance{}
	if m.server != nil {
		_ = m.server.proc.Stop()
		m.server = nil
	}
	m.mu.Unlock()
	removeFirewall(context.Background())
}

// IsRunning reports whether inbound id's MTProxy engine is currently running.
func (m *Manager) IsRunning(id int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.mtproxies[id]
	return ok && cur.proc.IsRunning()
}
