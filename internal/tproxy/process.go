package tproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

var (
	gracefulStopTimeout = 5 * time.Second
	forceStopTimeout    = 2 * time.Second
	startupTimeout      = 10 * time.Second
)

// procLogWriter forwards a child's stdout/stderr into the panel log a line at
// a time, and remembers the most recent one for GetResult.
type procLogWriter struct {
	mu       sync.Mutex
	label    string
	buf      string
	lastLine string
}

func (w *procLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := w.buf[:i]
		w.buf = w.buf[i+1:]
		w.emitLocked(line)
	}
	return len(p), nil
}

// Flush emits a buffered partial line, called once the process exits so a
// final un-terminated error line is not lost.
func (w *procLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != "" {
		line := w.buf
		w.buf = ""
		w.emitLocked(line)
	}
}

func (w *procLogWriter) emitLocked(line string) {
	trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
	if trimmed == "" {
		return
	}
	w.lastLine = trimmed
	logger.Infof("tproxy: %s | %s", w.label, trimmed)
}

func (w *procLogWriter) LastLine() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastLine
}

// childProcess supervises one external binary invocation -- either the one
// shared tproxy-server relay or one inbound's MTProxy engine.
type childProcess struct {
	mu              sync.RWMutex
	cmd             *exec.Cmd
	done            chan struct{}
	binaryPath      string
	args            []string
	readyAddr       string // loopback "ip:port" WaitReady polls
	logWriter       *procLogWriter
	exitErr         error
	intentionalStop atomic.Bool
}

func newChildProcess(binaryPath string, args []string, readyAddr, label string) *childProcess {
	return &childProcess{
		binaryPath: binaryPath,
		args:       args,
		readyAddr:  readyAddr,
		logWriter:  &procLogWriter{label: label},
	}
}

// IsRunning reports whether the child process is currently running.
func (p *childProcess) IsRunning() bool {
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
func (p *childProcess) GetResult() string {
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

// Start launches the process and returns once the OS process exists, without
// confirming it is actually serving -- see WaitReady.
func (p *childProcess) Start() error {
	if p.IsRunning() {
		return errors.New("already running")
	}
	cmd := exec.Command(p.binaryPath, p.args...)
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

// WaitReady blocks until readyAddr accepts a connection, so a caller never
// observes a "running" instance that is not actually serving yet.
func (p *childProcess) WaitReady() error {
	return waitForListener(p.readyAddr, p)
}

func (p *childProcess) wait(cmd *exec.Cmd, done chan struct{}) {
	defer close(done)
	err := cmd.Wait()
	p.logWriter.Flush()
	if err == nil || p.intentionalStop.Load() {
		return
	}
	logger.Errorf("tproxy: %s process exited: %v", p.logWriter.label, err)
	p.mu.Lock()
	p.exitErr = err
	p.mu.Unlock()
}

// Stop terminates the process gracefully, falling back to a kill.
func (p *childProcess) Stop() error {
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

	logger.Warningf("tproxy: %s did not stop after SIGTERM, killing process", p.logWriter.label)
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return waitForExit(done, forceStopTimeout)
}

func waitForExit(done <-chan struct{}, timeout time.Duration) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("timed out waiting for the process to stop")
	}
}

// readyChecker is the minimal surface waitForListener needs.
type readyChecker interface {
	IsRunning() bool
	GetResult() string
}

// readyWaiter is the common surface Manager awaits outside its lock.
type readyWaiter interface {
	WaitReady() error
}

// waitForListener blocks until addr accepts a connection, giving up early if
// the process died.
func waitForListener(addr string, proc readyChecker) error {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: time.Second}
	for {
		if !proc.IsRunning() {
			return fmt.Errorf("process exited during startup: %s", proc.GetResult())
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("did not start listening on %s: %s", addr, proc.GetResult())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
