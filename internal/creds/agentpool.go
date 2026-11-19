package creds

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SessionAgent is a per-session in-memory ssh-agent listening on a UNIX
// socket. The socket is bind-mounted into the session container; the private
// keys stay inside the gateway process for the whole agent lifetime.
type SessionAgent struct {
	SessionID string
	Socket    string

	agent  agent.Agent
	ln     net.Listener
	done   chan struct{}
	closed sync.Once
}

// SocketName is the container-side path the socket is mounted at.
const SocketName = "/ssh-agent/agent.sock"

// AgentPool tracks session agents and their sockets.
type AgentPool struct {
	dir string

	mu       sync.Mutex
	sessions map[string]*SessionAgent
}

// NewAgentPool prepares the pool and wipes stale sockets left behind by a
// previous gateway process (startup self-healing).
func NewAgentPool(dir string) (*AgentPool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return &AgentPool{dir: dir, sessions: map[string]*SessionAgent{}}, nil
}

// StartSession creates an agent holding the given private keys for one
// session. Keys are expected to be fully parsed (crypto.PrivateKey values);
// plaintext key material must have been zeroed by the caller.
func (p *AgentPool) StartSession(sessionID string, privateKeys []any) (*SessionAgent, error) {
	if len(privateKeys) == 0 {
		return nil, fmt.Errorf("no keys for session %s", sessionID)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.sessions[sessionID]; ok {
		return existing, nil
	}
	sock := filepath.Join(p.dir, sessionID+".sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sock, err)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	sa := &SessionAgent{
		SessionID: sessionID,
		Socket:    sock,
		agent:     agent.NewKeyring(),
		ln:        ln,
		done:      make(chan struct{}),
	}
	for _, k := range privateKeys {
		if err := sa.agent.Add(agent.AddedKey{PrivateKey: k, Comment: "git-mcp:" + sessionID}); err != nil {
			ln.Close()
			return nil, fmt.Errorf("add key: %w", err)
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(sa.done)
				return
			}
			go func(c net.Conn) {
				_ = agent.ServeAgent(sa.agent, c)
				_ = c.Close()
			}(conn)
		}
	}()
	p.sessions[sessionID] = sa
	return sa, nil
}

// AddKey appends a key to a live session agent (e.g. a submodule repository
// key that became necessary mid-session).
func (sa *SessionAgent) AddKey(k any) error {
	return sa.agent.Add(agent.AddedKey{PrivateKey: k, Comment: "git-mcp"})
}

// CloseSession stops the agent, removes its socket and forgets the session.
func (p *AgentPool) CloseSession(sessionID string) {
	p.mu.Lock()
	sa, ok := p.sessions[sessionID]
	if ok {
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()
	if ok {
		sa.closed.Do(func() {
			_ = sa.ln.Close()
			_ = os.Remove(sa.Socket)
		})
	}
}

// Get returns the session agent, if it exists.
func (p *AgentPool) Get(sessionID string) (*SessionAgent, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sa, ok := p.sessions[sessionID]
	return sa, ok
}

// SessionCount reports the number of live session agents.
func (p *AgentPool) SessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// ParseRawPrivateKey parses an OpenSSH PEM block into a crypto private key.
// The caller is responsible for zeroing the plaintext input afterwards.
func ParseRawPrivateKey(plain []byte) (any, error) {
	return ssh.ParseRawPrivateKey(plain)
}
