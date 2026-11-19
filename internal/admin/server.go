// Package admin serves the embedded management console and its JSON API on
// the same port as the MCP endpoint, guarded by the admin token.
package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/creds"
	"github.com/local/git-mcp-gateway/internal/repo"
	"github.com/local/git-mcp-gateway/internal/sanitize"
	"github.com/local/git-mcp-gateway/internal/session"
)

//go:embed all:static
var staticFS embed.FS

// Server is the admin console.
type Server struct {
	Store   *config.Store
	Auth    *auth.Authenticator
	Audit   *audit.Logger
	Repos   *repo.Manager
	Sess    *session.Manager
	Pool    interface{ SessionCount() int }
	Version string
}

// Register wires the console into an http mux under /admin.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/admin/", s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin")
	if strings.HasPrefix(path, "/api/") {
		s.api(w, r, strings.TrimPrefix(path, "/api"))
		return
	}
	if path == "/" || path == "" {
		path = "/index.html"
	}
	data, err := staticFS.ReadFile("static" + path)
	if err != nil {
		// SPA fallback to the page itself
		data, err = staticFS.ReadFile("static/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	switch {
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	_, _ = w.Write(data)
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, rest string) {
	if err := s.Auth.Admin(r); err != nil {
		s.Audit.Log(audit.Event{Actor: "-", ActorType: "admin", Event: "authn",
			Result: "denied", Detail: "admin api without valid token: " + r.Method + " " + rest})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch {
	case rest == "overview" && r.Method == http.MethodGet:
		s.overview(w, r)
	case rest == "users" && r.Method == http.MethodGet:
		s.listUsers(w, r)
	case rest == "users" && r.Method == http.MethodPost:
		s.createUser(w, r)
	case strings.HasPrefix(rest, "users/") && strings.HasSuffix(rest, "/rotate") && r.Method == http.MethodPost:
		s.rotateUser(w, r, strings.TrimSuffix(strings.TrimPrefix(rest, "users/"), "/rotate"))
	case strings.HasPrefix(rest, "users/") && r.Method == http.MethodDelete:
		s.deleteUser(w, r, strings.TrimPrefix(rest, "users/"))
	case rest == "repos" && r.Method == http.MethodGet:
		s.listRepos(w, r)
	case rest == "repos" && r.Method == http.MethodPost:
		s.upsertRepo(w, r)
	case strings.HasPrefix(rest, "repos/") && r.Method == http.MethodDelete:
		s.deleteRepo(w, r, strings.TrimPrefix(rest, "repos/"))
	case rest == "credentials" && r.Method == http.MethodGet:
		s.listCredentials(w, r)
	case rest == "credentials" && r.Method == http.MethodPost:
		s.createCredential(w, r)
	case strings.HasPrefix(rest, "credentials/") && r.Method == http.MethodDelete:
		s.deleteCredential(w, r, strings.TrimPrefix(rest, "credentials/"))
	case rest == "grants" && r.Method == http.MethodGet:
		s.getGrants(w, r)
	case rest == "grants" && r.Method == http.MethodPut:
		s.putGrants(w, r)
	case rest == "audit" && r.Method == http.MethodGet:
		s.listAudit(w, r)
	case rest == "locks/unlock" && r.Method == http.MethodPost:
		s.unlock(w, r)
	case rest == "workspace/fix" && r.Method == http.MethodPost:
		s.fixWorkspace(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get()
	type userView struct {
		Name, Email string
		Disabled    bool
	}
	users := []userView{}
	for name, u := range cfg.Users {
		users = append(users, userView{Name: name, Email: u.Email, Disabled: u.Disabled})
	}
	type repoView struct {
		ID, GitHub, Dir, DefaultBranch string
	}
	repos := []repoView{}
	for id, rr := range cfg.Repos {
		dir, _ := cfg.DirFor(id)
		repos = append(repos, repoView{ID: id, GitHub: rr.GitHub, Dir: dir, DefaultBranch: rr.DefaultBranch})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.Version,
		"users":    users,
		"repos":    repos,
		"grants":   cfg.Grants,
		"locks":    s.Repos.Snapshot(),
		"sessions": s.Sess.ActiveSessions(),
		"agents":   s.Pool.SessionCount(),
	})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get()
	out := []map[string]any{}
	for name, u := range cfg.Users {
		out = append(out, map[string]any{"name": name, "email": u.Email, "disabled": u.Disabled})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Email string }
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if in.Name == "" || in.Email == "" {
		writeJSON(w, 400, map[string]string{"error": "name and email are required"})
		return
	}
	token, err := newToken()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	hash, err := auth.HashToken(token)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	err = s.Store.Update(func(c *config.Config) error {
		if _, exists := c.Users[in.Name]; exists {
			return fmt.Errorf("user %q already exists", in.Name)
		}
		c.Users[in.Name] = config.User{TokenHash: hash, Name: in.Name, Email: in.Email}
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "user "+in.Name+" created")
	writeJSON(w, http.StatusOK, map[string]string{"name": in.Name, "token": token})
}

func (s *Server) rotateUser(w http.ResponseWriter, r *http.Request, name string) {
	token, err := newToken()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	hash, err := auth.HashToken(token)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	err = s.Store.Update(func(c *config.Config) error {
		u, ok := c.Users[name]
		if !ok {
			return fmt.Errorf("user %q not found", name)
		}
		u.TokenHash = hash
		c.Users[name] = u
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "token rotated for "+name)
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "token": token})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, name string) {
	err := s.Store.Update(func(c *config.Config) error {
		if _, ok := c.Users[name]; !ok {
			return fmt.Errorf("user %q not found", name)
		}
		delete(c.Users, name)
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if g.User != name {
				kept = append(kept, g)
			}
		}
		c.Grants = kept
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "user deleted: "+name)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get()
	writeJSON(w, http.StatusOK, cfg.Repos)
}

func (s *Server) upsertRepo(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, GitHub, Dir, DefaultBranch string }
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if in.ID == "" || !strings.Contains(in.GitHub, "/") {
		writeJSON(w, 400, map[string]string{"error": "id and github (org/name) are required"})
		return
	}
	err := s.Store.Update(func(c *config.Config) error {
		c.Repos[in.ID] = config.Repo{GitHub: in.GitHub, Dir: in.Dir, DefaultBranch: in.DefaultBranch}
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "repo upserted: "+in.ID)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) deleteRepo(w http.ResponseWriter, r *http.Request, id string) {
	err := s.Store.Update(func(c *config.Config) error {
		if _, ok := c.Repos[id]; !ok {
			return fmt.Errorf("repo %q not found", id)
		}
		delete(c.Repos, id)
		for n, cred := range c.Credentials {
			if cred.Repo == id {
				delete(c.Credentials, n)
			}
		}
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if g.Repo != id {
				kept = append(kept, g)
			}
		}
		c.Grants = kept
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "repo deleted: "+id)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get()
	out := []map[string]any{}
	for name, c := range cfg.Credentials {
		out = append(out, map[string]any{"name": name, "repo": c.Repo, "readonly": c.ReadOnly, "key_file": c.KeyFile})
	}
	writeJSON(w, http.StatusOK, out)
}

// createCredential generates a fresh ed25519 deploy key, stores the private
// key encrypted and returns the public key once for GitHub registration.
func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Repo string
		ReadOnly   bool
	}
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if in.Name == "" || in.Repo == "" {
		writeJSON(w, 400, map[string]string{"error": "name and repo are required"})
		return
	}
	cfg := s.Store.Get()
	if _, ok := cfg.Repos[in.Repo]; !ok {
		writeJSON(w, 400, map[string]string{"error": "unknown repo " + in.Repo})
		return
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	block, err := ssh.MarshalPrivateKey(priv, "git-mcp:"+in.Name)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	pemText := pem.EncodeToMemory(block)
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	key, err := creds.GlobalMasterKey()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	blob, err := creds.Encrypt(key, pemText)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	keyFile := "/keys/" + in.Name + ".age"
	if err := osWriteFile(keyFile, []byte(blob)); err != nil {
		writeJSON(w, 500, map[string]string{"error": "write key file: " + err.Error()})
		return
	}
	err = s.Store.Update(func(c *config.Config) error {
		if _, exists := c.Credentials[in.Name]; exists {
			return fmt.Errorf("credential %q already exists", in.Name)
		}
		c.Credentials[in.Name] = config.Credential{Repo: in.Repo, ReadOnly: in.ReadOnly, KeyFile: keyFile}
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	sshPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPubKey)))
	fingerprint := ssh.FingerprintSHA256(sshPubKey)
	s.audit("admin", "config", "credential created: "+in.Name+" ("+in.Repo+")")
	writeJSON(w, http.StatusOK, map[string]string{
		"name": in.Name, "repo": in.Repo, "readonly": fmt.Sprintf("%v", in.ReadOnly),
		"public_key": sshPub, "fingerprint": fingerprint,
		"note": "register this public key as a deploy key on the GitHub repository, then the gateway can use it",
	})
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request, name string) {
	err := s.Store.Update(func(c *config.Config) error {
		if _, ok := c.Credentials[name]; !ok {
			return fmt.Errorf("credential %q not found", name)
		}
		delete(c.Credentials, name)
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if g.Credential != name {
				kept = append(kept, g)
			}
		}
		c.Grants = kept
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", "credential deleted: "+name)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) getGrants(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get()
	writeJSON(w, http.StatusOK, map[string]any{"credentials": cfg.Credentials, "grants": cfg.Grants})
}

func (s *Server) putGrants(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Grants []config.Grant `json:"grants"`
	}
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	err := s.Store.Update(func(c *config.Config) error {
		c.Grants = in.Grants
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "config", fmt.Sprintf("grants replaced (%d entries)", len(in.Grants)))
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("n"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	writeJSON(w, http.StatusOK, s.Audit.Recent(n))
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
	}
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var freed []string
	for _, l := range s.Repos.Snapshot() {
		if l.Repo != in.Repo {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		s.Sess.Destroy(ctx, l.SessionID, l.Repo)
		cancel()
		s.Repos.Release(l.Repo, l.SessionID)
		freed = append(freed, l.SessionID)
	}
	s.audit("admin", "admin", "forced unlock of "+in.Repo+" (sessions: "+strings.Join(freed, ",")+")")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "released_sessions": freed})
}

func (s *Server) sessionHasContainers(repo string) bool {
	for _, a := range s.Sess.ActiveSessions() {
		if a.Repo == repo {
			return true
		}
	}
	return false
}

func (s *Server) fixWorkspace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
	}
	if err := decode(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	removed, err := s.Repos.FixWorkspace(in.Repo)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit("admin", "admin", "workspace fix for "+in.Repo+": removed "+strings.Join(removed, ","))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

func (s *Server) audit(actor, actorType, detail string) {
	s.Audit.Log(audit.Event{Actor: actor, ActorType: actorType, Event: "config",
		Result: "ok", Detail: sanitize.Clean(detail), TS: time.Now()})
}

// osWriteFile is a hook so the key path (/keys) stays configurable in tests.
var osWriteFile = func(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
