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

// NamedKey pairs a parsed private key with the name of the credential it was
// loaded from, so a session agent never re-adds (or re-decrypts) the same
// credential twice.
type NamedKey struct {
	Name string
	Key  any
}

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
	keys   map[string]bool // credential names already added
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
// session, or returns the live agent if the session already exists. Keys are
// expected to be fully parsed (crypto.PrivateKey values); plaintext key
// material must have been zeroed by the caller. Keys whose credential name is
// already loaded are skipped.
func (p *AgentPool) StartSession(sessionID string, keys []NamedKey) (*SessionAgent, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys for session %s", sessionID)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.sessions[sessionID]; ok {
		for _, k := range keys {
			if existing.keys[k.Name] {
				continue
			}
			if err := existing.agent.Add(agent.AddedKey{PrivateKey: k.Key, Comment: "git-mcp:" + sessionID}); err != nil {
				return nil, fmt.Errorf("add key: %w", err)
			}
			existing.keys[k.Name] = true
		}
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
		keys:      map[string]bool{},
	}
	for _, k := range keys {
		if err := sa.agent.Add(agent.AddedKey{PrivateKey: k.Key, Comment: "git-mcp:" + sessionID}); err != nil {
			ln.Close()
			return nil, fmt.Errorf("add key: %w", err)
		}
		sa.keys[k.Name] = true
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

// MissingKeys returns the credential names not yet loaded into the session
// agent, so callers only decrypt what is actually needed. When the session
// agent does not exist yet, every requested name is considered missing.
func (p *AgentPool) MissingKeys(sessionID string, names []string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	sa, ok := p.sessions[sessionID]
	if !ok {
		return names
	}
	var out []string
	for _, n := range names {
		if !sa.keys[n] {
			out = append(out, n)
		}
	}
	return out
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
