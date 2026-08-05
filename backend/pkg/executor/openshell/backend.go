package openshell

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"pentagi/pkg/config"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"golang.org/x/crypto/ssh"
)

// execState holds the result of a completed exec operation.
type execState struct {
	output   []byte
	exitCode int
	done     chan struct{}
}

// Backend implements executor.Backend over SSH to an OpenShell sandbox.
// It synthesizes Docker-compatible types so the terminal tool works without modification.
type Backend struct {
	cli      *CLI
	sessions *SessionManager
	cfg      *config.Config
	preset   string

	mu      sync.Mutex
	execs   map[string]*execState // execID → state
	counter atomic.Int64
}

// NewBackend creates an OpenShell executor backend.
func NewBackend(cfg *config.Config) (*Backend, error) {
	if cfg.OpenShellSSHKeyPath == "" {
		return nil, fmt.Errorf("OPENSHELL_SSH_KEY_PATH is required when OpenShell is enabled")
	}

	sessions, err := NewSessionManager(
		cfg.OpenShellHost,
		cfg.OpenShellSSHPort,
		cfg.OpenShellSSHUser,
		cfg.OpenShellSSHKeyPath,
		cfg.OpenShellKnownHostsPath,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session manager: %w", err)
	}

	cli := NewCLI(cfg.OpenShellCLIPath, cfg.OpenShellHost)

	return &Backend{
		cli:      cli,
		sessions: sessions,
		cfg:      cfg,
		preset:   cfg.OpenShellDefaultPreset,
		execs:    make(map[string]*execState),
	}, nil
}

// ContainerExecCreate creates a synthetic exec process that runs a command over SSH.
// The "container" name is treated as the sandbox name.
func (b *Backend) ContainerExecCreate(ctx context.Context, name string, opts container.ExecOptions) (container.ExecCreateResponse, error) {
	execID := fmt.Sprintf("openshell-exec-%d", b.counter.Add(1))

	state := &execState{
		done: make(chan struct{}),
	}

	// Run the command in a background goroutine
	go func() {
		defer close(state.done)

		session, err := b.sessions.GetOrConnect(name)
		if err != nil {
			state.output = []byte(fmt.Sprintf("SSH connection failed: %v", err))
			state.exitCode = 1
			return
		}

		sshSession, err := session.Client.NewSession()
		if err != nil {
			state.output = []byte(fmt.Sprintf("SSH session creation failed: %v", err))
			state.exitCode = 1
			return
		}
		defer sshSession.Close()

		if opts.Tty {
			modes := ssh.TerminalModes{
				ssh.ECHO:          0,
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
			}
			if err := sshSession.RequestPty("xterm", 80, 200, modes); err != nil {
				state.output = []byte(fmt.Sprintf("PTY request failed: %v", err))
				state.exitCode = 1
				return
			}
		}

		// Build the command string
		cmd := buildCommand(opts.Cmd, opts.WorkingDir)

		var out bytes.Buffer
		sshSession.Stdout = &out
		sshSession.Stderr = &out

		err = sshSession.Run(cmd)
		state.output = out.Bytes()

		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				state.exitCode = exitErr.ExitStatus()
			} else {
				state.exitCode = 1
			}
		}
	}()

	b.mu.Lock()
	b.execs[execID] = state
	b.mu.Unlock()

	return container.ExecCreateResponse{ID: execID}, nil
}

// ContainerExecAttach returns a HijackedResponse that streams the exec output.
// It blocks until the exec process completes or the context is cancelled.
func (b *Backend) ContainerExecAttach(ctx context.Context, execID string, _ container.ExecAttachOptions) (types.HijackedResponse, error) {
	b.mu.Lock()
	state, ok := b.execs[execID]
	b.mu.Unlock()

	if !ok {
		return types.HijackedResponse{}, fmt.Errorf("exec %q not found", execID)
	}

	// Wait for the exec to complete or context cancellation
	select {
	case <-state.done:
	case <-ctx.Done():
		return types.HijackedResponse{}, ctx.Err()
	}

	// Create a pipe that the caller reads from
	pr, pw := net.Pipe()
	go func() {
		pw.Write(state.output)
		pw.Close()
	}()

	return types.HijackedResponse{
		Conn:   pr,
		Reader: bufio.NewReader(bytes.NewReader(state.output)),
	}, nil
}

// ContainerExecInspect returns the exit status of a completed exec.
func (b *Backend) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	b.mu.Lock()
	state, ok := b.execs[execID]
	b.mu.Unlock()

	if !ok {
		return container.ExecInspect{}, fmt.Errorf("exec %q not found", execID)
	}

	// Wait for completion
	select {
	case <-state.done:
	case <-ctx.Done():
		return container.ExecInspect{Running: true}, ctx.Err()
	}

	// Clean up the exec state
	b.mu.Lock()
	delete(b.execs, execID)
	b.mu.Unlock()

	return container.ExecInspect{
		ExitCode: state.exitCode,
		Running:  false,
	}, nil
}

// CopyToContainer writes a tar archive to the sandbox via SSH + tar extraction.
func (b *Backend) CopyToContainer(ctx context.Context, containerID string, dstPath string, content io.Reader, _ container.CopyToContainerOptions) error {
	session, err := b.sessions.GetOrConnect(containerID)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	sshSession, err := session.Client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session creation failed: %w", err)
	}
	defer sshSession.Close()

	sshSession.Stdin = content

	// Extract tar archive at destination path
	cmd := fmt.Sprintf("mkdir -p %s && tar -xf - -C %s", shellQuote(dstPath), shellQuote(dstPath))
	if out, err := sshSession.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("tar extraction failed at %s: %s: %w", dstPath, string(out), err)
	}

	return nil
}

// CopyFromContainer reads a path from the sandbox as a tar archive over SSH.
func (b *Backend) CopyFromContainer(ctx context.Context, containerID string, srcPath string) (io.ReadCloser, container.PathStat, error) {
	session, err := b.sessions.GetOrConnect(containerID)
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("SSH connection failed: %w", err)
	}

	sshSession, err := session.Client.NewSession()
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("SSH session creation failed: %w", err)
	}

	// Create a tar of the source path and stream it back
	cmd := fmt.Sprintf("tar -cf - -C $(dirname %s) $(basename %s)", shellQuote(srcPath), shellQuote(srcPath))

	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		sshSession.Close()
		return nil, container.PathStat{}, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := sshSession.Start(cmd); err != nil {
		sshSession.Close()
		return nil, container.PathStat{}, fmt.Errorf("failed to start tar read: %w", err)
	}

	// Wrap in a ReadCloser that also waits for the session to finish
	rc := &sshReadCloser{
		Reader:  stdout,
		session: sshSession,
	}

	return rc, container.PathStat{Name: srcPath}, nil
}

// IsContainerRunning checks if the sandbox is accessible via SSH.
func (b *Backend) IsContainerRunning(ctx context.Context, containerID string) (bool, error) {
	session, err := b.sessions.GetOrConnect(containerID)
	if err != nil {
		return false, nil
	}

	sshSession, err := session.Client.NewSession()
	if err != nil {
		return false, nil
	}
	defer sshSession.Close()

	err = sshSession.Run("true")
	return err == nil, nil
}

// GetDefaultImage returns the default sandbox preset name (used for provisioning).
func (b *Backend) GetDefaultImage() string {
	return b.preset
}

// Cleanup disconnects all SSH sessions and deletes managed sandboxes.
func (b *Backend) Cleanup(ctx context.Context, sandboxNames []string) {
	for _, name := range sandboxNames {
		b.sessions.Close(name)
		// Best-effort sandbox deletion
		_ = b.cli.DeleteSandbox(ctx, name)
	}
}

// sshReadCloser wraps an SSH stdout reader and cleans up the session on Close.
type sshReadCloser struct {
	io.Reader
	session *ssh.Session
}

func (r *sshReadCloser) Close() error {
	_ = r.session.Wait()
	r.session.Close()
	return nil
}

// buildCommand constructs a shell command from the exec options.
func buildCommand(cmd []string, workingDir string) string {
	if len(cmd) == 0 {
		return "true"
	}

	cmdStr := strings.Join(cmd, " ")
	if workingDir != "" {
		cmdStr = fmt.Sprintf("cd %s && %s", shellQuote(workingDir), cmdStr)
	}

	return cmdStr
}

// shellQuote returns a safely quoted shell argument.
func shellQuote(s string) string {
	// Use single quotes, escaping any existing single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
