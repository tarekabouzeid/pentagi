package openshell

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Session holds an SSH connection to a single OpenShell sandbox.
type Session struct {
	Name   string
	Client *ssh.Client
}

// SessionManager maintains SSH connections to OpenShell sandboxes.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session // keyed by sandbox name
	config   *ssh.ClientConfig
	host     string
	port     int
}

// NewSessionManager creates a session manager with the given SSH configuration.
func NewSessionManager(host string, port int, user, keyPath, knownHostsPath string) (*SessionManager, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key %q: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	var hostKeyCallback ssh.HostKeyCallback
	if knownHostsPath != "" {
		hostKeyCallback, err = knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts from %q: %w", knownHostsPath, err)
		}
	} else {
		return nil, fmt.Errorf("OPENSHELL_KNOWN_HOSTS_PATH must be set for SSH host-key verification; refusing to connect without host-key checking")
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	return &SessionManager{
		sessions: make(map[string]*Session),
		config:   sshConfig,
		host:     host,
		port:     port,
	}, nil
}

// GetOrConnect returns an existing session or dials a new one for the sandbox.
func (sm *SessionManager) GetOrConnect(name string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.sessions[name]; ok {
		// Verify the connection is still alive
		_, _, err := s.Client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return s, nil
		}
		// Connection dead, remove and reconnect
		s.Client.Close()
		delete(sm.sessions, name)
	}

	addr := fmt.Sprintf("%s:%d", sm.host, sm.port)
	client, err := ssh.Dial("tcp", addr, sm.config)
	if err != nil {
		return nil, fmt.Errorf("failed to SSH into sandbox %q at %s: %w", name, addr, err)
	}

	s := &Session{
		Name:   name,
		Client: client,
	}
	sm.sessions[name] = s
	return s, nil
}

// Close disconnects a specific session.
func (sm *SessionManager) Close(name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.sessions[name]; ok {
		s.Client.Close()
		delete(sm.sessions, name)
	}
}

// CloseAll disconnects all sessions.
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for name, s := range sm.sessions {
		s.Client.Close()
		delete(sm.sessions, name)
	}
}
