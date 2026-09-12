package naiveproxy

import (
	"fmt"
	"os"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

func configDir() string             { return Dir() }
func configPathForID(id int) string { return fmt.Sprintf("%s/Caddyfile-%d", configDir(), id) }

// managed pairs a running process with the exact Caddyfile text it was
// started from, so ensureLocked can tell "nothing changed" from "restart needed".
type managed struct {
	proc        *Process
	fingerprint string
}

// Manager owns every Naive-backed inbound's Caddy process, one per inbound,
// mirroring internal/mtproto's Manager shape.
type Manager struct {
	mu    sync.Mutex
	procs map[int]*managed
	swept bool
}

var (
	managerOnce sync.Once
	manager     *Manager
)

// GetManager returns the process-wide NaiveProxy manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() { manager = &Manager{procs: map[int]*managed{}} })
	return manager
}

// sweepOrphansLocked kills stray caddy processes from a previous run, once
// per process lifetime -- before m.procs is trusted as the full picture.
func (m *Manager) sweepOrphansLocked() {
	if m.swept {
		return
	}
	m.swept = true
	if n := killStrayCaddyProcesses(BinPath()); n > 0 {
		logger.Warningf("naiveproxy: terminated %d orphaned caddy process(es) from a previous run", n)
	}
}

// Ensure brings the running process for inst.Id in line with inst.
func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	m.sweepOrphansLocked()
	proc, err := m.ensureLocked(inst)
	m.mu.Unlock()
	if err != nil || proc == nil {
		return err
	}
	return m.awaitReady(inst.Id, proc)
}

// ensureLocked is Ensure's fast, non-blocking part; returns the freshly
// spawned process to await outside the lock, nil if nothing new started.
func (m *Manager) ensureLocked(inst Instance) (*Process, error) {
	if len(inst.Clients) == 0 {
		m.removeLocked(inst.Id)
		return nil, nil
	}

	fp, err := renderCaddyfile(inst)
	if err != nil {
		return nil, err
	}

	if cur, ok := m.procs[inst.Id]; ok {
		if cur.proc.IsRunning() && cur.fingerprint == fp {
			return nil, nil
		}
		_ = cur.proc.Stop()
		delete(m.procs, inst.Id)
	}

	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return nil, fmt.Errorf("naiveproxy: cannot create %s: %w", configDir(), err)
	}
	cfgPath := configPathForID(inst.Id)
	if err := os.WriteFile(cfgPath, []byte(fp), 0o600); err != nil {
		return nil, fmt.Errorf("naiveproxy: cannot write %s: %w", cfgPath, err)
	}

	proc := newProcess(cfgPath, inst.ListenAddr, fmt.Sprintf("inbound %d", inst.Id))
	if err := proc.Start(); err != nil {
		return nil, err
	}
	m.procs[inst.Id] = &managed{proc: proc, fingerprint: fp}
	return proc, nil
}

// awaitReady blocks (outside m.mu) until proc is actually serving, tearing
// it back down on failure so a half-started instance is never left tracked.
func (m *Manager) awaitReady(id int, proc *Process) error {
	if err := proc.WaitReady(); err != nil {
		m.Remove(id)
		return fmt.Errorf("naiveproxy: inbound %d: %w", id, err)
	}
	logger.Infof("naiveproxy: started caddy for inbound %d", id)
	return nil
}

// Remove stops and forgets the Caddy process for an inbound id.
func (m *Manager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(id)
}

func (m *Manager) removeLocked(id int) {
	cur, ok := m.procs[id]
	if !ok {
		return
	}
	_ = cur.proc.Stop()
	delete(m.procs, id)
	_ = os.Remove(configPathForID(id))
	logger.Infof("naiveproxy: stopped caddy for inbound %d", id)
}

// Reconcile drives the running set toward desired -- spawns happen under
// m.mu, readiness waits after releasing it, so one slow instance can't stall the rest.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	m.sweepOrphansLocked()

	want := make(map[int]struct{}, len(desired))
	for _, inst := range desired {
		want[inst.Id] = struct{}{}
	}
	for id := range m.procs {
		if _, ok := want[id]; !ok {
			m.removeLocked(id)
		}
	}

	type pending struct {
		id   int
		proc *Process
	}
	var toAwait []pending
	for _, inst := range desired {
		proc, err := m.ensureLocked(inst)
		if err != nil {
			logger.Warningf("naiveproxy: reconcile failed for inbound %d: %v", inst.Id, err)
			continue
		}
		if proc != nil {
			toAwait = append(toAwait, pending{inst.Id, proc})
		}
	}
	m.mu.Unlock()

	for _, p := range toAwait {
		if err := m.awaitReady(p.id, p.proc); err != nil {
			logger.Warningf("naiveproxy: %v", err)
		}
	}
}

// StopAll stops every managed Caddy process. Called on panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.procs {
		m.removeLocked(id)
	}
}

// IsRunning reports whether inbound id's Caddy process is currently running.
func (m *Manager) IsRunning(id int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.procs[id]
	return ok && cur.proc.IsRunning()
}
