package tproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// mtproxyProcess wraps one MTProxy engine invocation for one tproxy inbound.
type mtproxyProcess struct {
	mu              sync.RWMutex
	cmd             *exec.Cmd
	done            chan struct{}
	args            []string
	clientAddr      string // loopback "127.0.0.1:<-H port>", polled by WaitReady
	logWriter       *procLogWriter
	exitErr         error
	intentionalStop atomic.Bool
}

func newMTProxyProcess(args []string, clientAddr string, label string) *mtproxyProcess {
	return &mtproxyProcess{
		args:       args,
		clientAddr: clientAddr,
		logWriter:  &procLogWriter{label: label},
	}
}

// IsRunning reports whether the MTProxy process is currently running.
func (p *mtproxyProcess) IsRunning() bool {
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done != nil {
		select {
		case <-done:
			return false
		default:
		}
	}
	return true
}

// GetResult returns the last log line or the exit error from the process.
func (p *mtproxyProcess) GetResult() string {
	if line := p.logWriter.LastLine(); line != "" {
		return line
	}
	p.mu.RLock()
	exitErr := p.exitErr
	p.mu.RUnlock()
	if exitErr != nil {
		return exitErr.Error()
	}
	return ""
}

// Start launches the MTProxy engine and returns once the OS process exists,
// without confirming it is actually serving -- see WaitReady.
func (p *mtproxyProcess) Start() error {
	if p.IsRunning() {
		return errors.New("mtproxy is already running")
	}
	cmd := exec.CommandContext(context.Background(), mtproxyBinaryPath(), p.args...)
	cmd.Dir = dir()
	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter
	done := make(chan struct{})
	p.mu.Lock()
	p.cmd = cmd
	p.done = done
	p.exitErr = nil
	p.mu.Unlock()
	p.intentionalStop.Store(false)
	if err := cmd.Start(); err != nil {
		close(done)
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()
		return err
	}
	go p.wait(cmd, done)
	return nil
}

// WaitReady blocks until this engine's client port accepts a connection.
func (p *mtproxyProcess) WaitReady() error {
	return waitForListener(p.clientAddr, p)
}

func (p *mtproxyProcess) wait(cmd *exec.Cmd, done chan struct{}) {
	defer close(done)
	err := cmd.Wait()
	p.logWriter.Flush()
	if err == nil || p.intentionalStop.Load() {
		return
	}
	logger.Errorf("tproxy: mtproxy process exited: %v", err)
	p.mu.Lock()
	p.exitErr = err
	p.mu.Unlock()
}

// Stop terminates the process gracefully, falling back to a kill.
func (p *mtproxyProcess) Stop() error {
	if !p.IsRunning() {
		return nil
	}
	p.intentionalStop.Store(true)
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return waitForExit(done, forceStopTimeout)
		}
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return waitForExit(done, forceStopTimeout)
	}

	if err := waitForExit(done, gracefulStopTimeout); err == nil {
		return nil
	}

	logger.Warning("tproxy: mtproxy did not stop after SIGTERM, killing process")
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return waitForExit(done, forceStopTimeout)
}
