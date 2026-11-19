// Package mcpapi implements the MCP Streamable HTTP endpoint (a pragmatic
// JSON-RPC 2.0 subset: initialize, tools/list, tools/call, ping) plus the
// orchestration that turns a tool call into an audited, authorized git
// execution inside a session container.
package mcpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/creds"
	"github.com/local/git-mcp-gateway/internal/repo"
	"github.com/local/git-mcp-gateway/internal/session"
)

// Server is the MCP endpoint plus the session orchestrator.
type Server struct {
	Store   *config.Store
	Auth    *auth.Authenticator
	Audit   *audit.Logger
	Repos   *repo.Manager
	Sess    *session.Manager
	Pool    *creds.AgentPool
	Version string

	tools []toolDef

	sMu      sync.Mutex
	sessions map[string]*mcpSession
}

// New assembles the server and its tool catalogue.
func New(store *config.Store, authn *auth.Authenticator, auditL *audit.Logger,
	repos *repo.Manager, sess *session.Manager, pool *creds.AgentPool, version string) *Server {
	s := &Server{
		Store: store, Auth: authn, Audit: auditL, Repos: repos,
		Sess: sess, Pool: pool, Version: version,
		sessions: map[string]*mcpSession{},
	}
	s.initTools()
	return s
}

type mcpSession struct {
	ID       string
	User     string
	Name     string
	Email    string
	Created  time.Time
	LastSeen time.Time
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Register wires the endpoint into an http mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/mcp", s.handleMCP)
}

// StartReaper reaps idle session containers/locks/agents and stale MCP sessions.
func (s *Server) StartReaper(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reapOnce()
			}
		}
	}()
}

func (s *Server) reapOnce() {
	cfg := s.Store.Get()
	ttl := cfg.Server.SessionTTL
	for _, a := range s.Sess.ActiveSessions() {
		if time.Since(a.LastUsed) <= ttl {
			continue
		}
		s.Audit.Log(audit.Event{Actor: a.User, ActorType: "system", Event: "session",
			Repo: a.Repo, Session: a.SessionID, Result: "ok",
			Detail: "idle session reaped (container destroyed, lock released)"})
		s.teardownSessionRepo(a.SessionID, a.Repo)
	}
	// MCP sessions idle for a long time with no containers are dropped.
	s.sMu.Lock()
	for id, sess := range s.sessions {
		if time.Since(sess.LastSeen) > ttl && !s.sessionHasContainers(id) {
			delete(s.sessions, id)
		}
	}
	s.sMu.Unlock()
}

func (s *Server) sessionHasContainers(sessionID string) bool {
	for _, a := range s.Sess.ActiveSessions() {
		if a.SessionID == sessionID {
			return true
		}
	}
	return false
}

// teardownSessionRepo destroys the container, releases the lock and closes
// the agent when the session holds nothing else.
func (s *Server) teardownSessionRepo(sessionID, repoID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Sess.Destroy(ctx, sessionID, repoID)
	s.Repos.Release(repoID, sessionID)
	if !s.sessionHasContainers(sessionID) {
		s.Pool.CloseSession(sessionID)
	}
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	actor, _, authErr := s.Auth.User(r)
	if authErr != nil {
		s.Audit.Log(audit.Event{Actor: "-", ActorType: "user", Event: "authn", Result: "denied",
			Detail: "mcp call without valid token"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r, actor)
	case http.MethodDelete:
		s.handleDelete(w, r, actor)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, actor string) {
	sid := r.Header.Get("Mcp-Session-Id")
	s.sMu.Lock()
	sess, ok := s.sessions[sid]
	if ok && sess.User != actor {
		s.sMu.Unlock()
		s.Audit.Log(audit.Event{Actor: actor, ActorType: "user", Event: "authz",
			Session: sid, Result: "denied", Detail: "delete: session belongs to another user"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session belongs to another user"})
		return
	}
	if ok {
		delete(s.sessions, sid)
	}
	s.sMu.Unlock()
	if ok {
		for _, a := range s.Sess.ActiveSessions() {
			if a.SessionID == sid {
				s.teardownSessionRepo(sid, a.Repo)
			}
		}
		s.Audit.Log(audit.Event{Actor: actor, ActorType: "user", Event: "session",
			Session: sid, Result: "ok", Detail: "session closed"})
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request, actor string) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"),
			Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	// Notifications carry no id and never get a body back.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if req.Method == "initialize" {
		s.handleInitialize(w, r, actor, &req)
		return
	}

	sid := r.Header.Get("Mcp-Session-Id")
	sess, ok := s.lookup(sid)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	// The MCP session is bound to the authenticated caller: a valid token
	// alone must not grant access to somebody else's session id.
	if sess.User != actor {
		s.Audit.Log(audit.Event{Actor: actor, ActorType: "user", Event: "authz",
			Session: sid, Result: "denied", Detail: "session belongs to another user"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session belongs to another user"})
		return
	}

	switch req.Method {
	case "ping":
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage("{}")})
	case "tools/list":
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: mustJSON(map[string]any{"tools": s.toolDefs()})})
	case "tools/call":
		s.handleToolsCall(w, r, sess, &req)
	default:
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32601, Message: fmt.Sprintf("method %q not found", req.Method)}})
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, r *http.Request, actor string, req *rpcRequest) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &params)
	if params.ProtocolVersion == "" {
		params.ProtocolVersion = "2025-06-18"
	}
	sid := r.Header.Get("Mcp-Session-Id")
	s.sMu.Lock()
	existing, ok := s.sessions[sid]
	switch {
	case ok && existing.User != actor:
		s.sMu.Unlock()
		s.Audit.Log(audit.Event{Actor: actor, ActorType: "user", Event: "authz",
			Session: sid, Result: "denied", Detail: "initialize: session belongs to another user"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session belongs to another user"})
		return
	case ok:
		existing.LastSeen = time.Now()
	default:
		sid = uuid.NewString()
		s.sessions[sid] = &mcpSession{ID: sid, User: actor, Created: time.Now(), LastSeen: time.Now()}
	}
	sess := s.sessions[sid]
	s.sMu.Unlock()
	s.Audit.Log(audit.Event{Actor: actor, ActorType: "user", Event: "session",
		Session: sid, Result: "ok", Detail: "initialize (protocol " + params.ProtocolVersion + ")"})

	result := map[string]any{
		"protocolVersion": params.ProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": "git-mcp-gateway", "version": s.Version},
	}
	w.Header().Set("Mcp-Session-Id", sid)
	w.Header().Set("User-Identity", sess.User)
	writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: mustJSON(result)})
}

func (s *Server) lookup(sid string) (*mcpSession, bool) {
	s.sMu.Lock()
	defer s.sMu.Unlock()
	sess, ok := s.sessions[sid]
	if ok {
		sess.LastSeen = time.Now()
	}
	return sess, ok
}

func (s *Server) handleToolsCall(w http.ResponseWriter, r *http.Request, sess *mcpSession, req *rpcRequest) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32602, Message: "invalid params"}})
		return
	}
	def, ok := s.toolByName(params.Name)
	if !ok {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32602, Message: fmt.Sprintf("unknown tool %q", params.Name)}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.Store.Get().Server.ExecTimeout+30*time.Second)
	defer cancel()
	text, err := def.Run(ctx, &callCtx{s: s, sess: sess}, params.Arguments)
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
	if err != nil {
		result["isError"] = true
		result["content"] = []map[string]any{{"type": "text", "text": sanitizeErr(err)}}
	}
	writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: mustJSON(result)})
}

// callCtx carries what a tool implementation needs.
type callCtx struct {
	s    *Server
	sess *mcpSession
}

func (c *callCtx) user() string { return c.sess.User }
func (c *callCtx) sid() string  { return c.sess.ID }

func sanitizeErr(err error) string {
	msg := err.Error()
	// keep the sentinel prefix readable for the agent
	for _, want := range []string{repo.ErrLocked.Error()} {
		if strings.HasPrefix(msg, want) {
			return msg
		}
	}
	return strings.TrimSpace(sanitizeText(msg))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRPC(w http.ResponseWriter, code int, resp rpcResponse) {
	writeJSON(w, code, resp)
}

func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return data
}
