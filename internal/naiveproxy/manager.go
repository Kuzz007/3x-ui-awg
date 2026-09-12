// Package naiveproxy also owns the per-inbound Caddy process lifecycle: one
// Caddy instance per Naive-backed inbound, its Caddyfile rendered fresh from
// the inbound's current client list on every Ensure/Reconcile call. Mirrors
// internal/mtproto's Manager shape (one external process per inbound,
// restart-on-any-change reconcile) rather than internal/wireproxy's
// (single global toggle, no per-client concept) -- see the architecture-pivot
// notes in the project's own memory for why.
package naiveproxy

import (
	"fmt"
	"os"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

func configDir() string             { return config.GetBinFolderPath() + "/naiveproxy" }
func configPathForID(id int) string { return fmt.Sprintf("%s/Caddyfile-%d", configDir(), id) }

// managed pairs a running process with the exact Caddyfile text it was
// started from, so ensureLocked can tell "nothing changed" from "restart needed".
type managed struct {
	proc        *Process
	fingerprint string
}

// Manager owns every Naive-backed inbound's Caddy process for the whole install.
type Manager struct {
	mu    sync.Mutex
	procs map[int]*managed
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

// Ensure brings the running process for inst.Id in line with inst.
func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(inst)
}

// ensureLocked does the real work of Ensure (callers must hold m.mu); a
// client-less instance is stopped, not started -- an unauthenticated proxy is a live hole.
func (m *Manager) ensureLocked(inst Instance) error {
	if len(inst.Clients) == 0 {
		m.removeLocked(inst.Id)
		return nil
	}

	fp, err := renderCaddyfile(inst)
	if err != nil {
		return err
	}

	if cur, ok := m.procs[inst.Id]; ok {
		if cur.proc.IsRunning() && cur.fingerprint == fp {
			return nil
		}
		_ = cur.proc.Stop()
		delete(m.procs, inst.Id)
	}

	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return fmt.Errorf("naiveproxy: cannot create %s: %w", configDir(), err)
	}
	cfgPath := configPathForID(inst.Id)
	if err := os.WriteFile(cfgPath, []byte(fp), 0o600); err != nil {
		return fmt.Errorf("naiveproxy: cannot write %s: %w", cfgPath, err)
	}

	proc := newProcess(cfgPath, inst.ListenAddr, fmt.Sprintf("inbound %d", inst.Id))
	if err := proc.Start(); err != nil {
		return err
	}
	m.procs[inst.Id] = &managed{proc: proc, fingerprint: fp}
	logger.Infof("naiveproxy: started caddy for inbound %d on %s", inst.Id, inst.ListenAddr)
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

// Reconcile drives the running set toward desired -- used at boot and
// periodically to recover from crashes.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[int]struct{}, len(desired))
	for _, inst := range desired {
		want[inst.Id] = struct{}{}
	}
	for id := range m.procs {
		if _, ok := want[id]; !ok {
			m.removeLocked(id)
		}
	}
	for _, inst := range desired {
		if err := m.ensureLocked(inst); err != nil {
			logger.Warningf("naiveproxy: reconcile failed for inbound %d: %v", inst.Id, err)
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
