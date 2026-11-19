// Package config loads and validates git-mcp-gateway configuration files.
//
// Configuration lives in a directory with four YAML files:
//
//	users.yaml   — human accounts (bcrypt token hashes) + admin token hash
//	grants.yaml  — SSH credentials (deploy keys) and user→repo→action grants
//	repos.yaml   — workspace root and the workspace-subdirectory ↔ GitHub repo map
//	server.yaml  — runtime knobs (addr, TTLs, image, paths)
//
// All files are watched with fsnotify; a failed reload keeps the previous
// known-good configuration and reports the problem through the audit log.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Actions that may be granted on a repository.
const (
	ActionRead  = "read"
	ActionClone = "clone"
	ActionPush  = "push"
)

// Server holds runtime knobs.
type Server struct {
	Addr           string        `yaml:"addr"`          // listen address, e.g. ":8443"
	SessionImage   string        `yaml:"session_image"` // session container image
	SessionTTL     time.Duration `yaml:"session_ttl"`   // idle time before a session container is reaped
	ExecTimeout    time.Duration `yaml:"exec_timeout"`  // per git-command timeout
	MaxOutputBytes int           `yaml:"max_output_bytes"`
	SocketDir      string        `yaml:"socket_dir"`  // where session agent sockets live
	AuditFile      string        `yaml:"audit_file"`  // JSONL audit sink
	GitHubHost     string        `yaml:"github_host"` // normally github.com
	LogLevel       string        `yaml:"log_level"`
}

// User is a human/automation account that calls the gateway with a Bearer token.
type User struct {
	TokenHash string `yaml:"token_hash"` // bcrypt
	Name      string `yaml:"name"`       // GIT_AUTHOR_NAME
	Email     string `yaml:"email"`      // GIT_AUTHOR_EMAIL
	Disabled  bool   `yaml:"disabled"`
}

// Credential is a GitHub deploy key held by the gateway.
type Credential struct {
	Repo     string `yaml:"repo"`     // "org/name" this key is bound to
	ReadOnly bool   `yaml:"readonly"` // GitHub-side deploy key without write access
	KeyFile  string `yaml:"key_file"` // path to the age/secretbox-encrypted private key
}

// Grant binds a user to a repo with allowed actions and the credential to use.
type Grant struct {
	User       string   `yaml:"user"`
	Repo       string   `yaml:"repo"`       // "org/name", must match a repos entry
	Actions    []string `yaml:"actions"`    // subset of read/clone/push
	Credential string   `yaml:"credential"` // credential name
}

// Repo maps a tool-level repository identifier to a workspace subdirectory.
type Repo struct {
	GitHub        string `yaml:"github"`         // "org/name"
	Dir           string `yaml:"dir"`            // workspace subdirectory; defaults to the repo base name
	DefaultBranch string `yaml:"default_branch"` // used when cloning
}

// Config is the fully merged configuration.
type Config struct {
	Users         map[string]User       `yaml:"users"`
	AdminToken    string                `yaml:"admin_token_hash"`
	Credentials   map[string]Credential `yaml:"credentials"`
	Grants        []Grant               `yaml:"grants"`
	Repos         map[string]Repo       `yaml:"repos"`
	WorkspaceRoot string                `yaml:"workspace_root"`
	Server        Server                `yaml:"server"`
}

// GrantFor returns the grant for a user+repo pair, if any.
func (c *Config) GrantFor(user, repo string) (Grant, bool) {
	for _, g := range c.Grants {
		if g.User == user && g.Repo == repo {
			return g, true
		}
	}
	return Grant{}, false
}

// HasAction reports whether the grant allows the given action.
func (g Grant) HasAction(action string) bool {
	for _, a := range g.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// DirFor returns the workspace subdirectory for a repo identifier.
func (c *Config) DirFor(repo string) (string, error) {
	r, ok := c.Repos[repo]
	if !ok {
		return "", fmt.Errorf("unknown repo %q", repo)
	}
	if r.Dir == "" {
		_, name, _ := strings.Cut(repo, "/")
		return name, nil
	}
	return r.Dir, nil
}

// RepoPath returns the absolute host path of a repo workspace directory.
func (c *Config) RepoPath(repo string) (string, error) {
	dir, err := c.DirFor(repo)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.WorkspaceRoot, dir), nil
}

// Store keeps the current configuration behind a lock and supports hot reload.
type Store struct {
	dir string

	mu       sync.RWMutex
	cur      *Config
	onChange func(*Config)

	notify *fsnotify.Watcher
}

// NewStore loads the configuration directory and starts watching it.
func NewStore(dir string, onChange func(*Config)) (*Store, error) {
	s := &Store{dir: dir, onChange: onChange}
	if err := s.reload(); err != nil {
		return nil, err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(dir); err != nil {
		return nil, err
	}
	s.notify = w
	go s.watch()
	return s, nil
}

// Get returns the current configuration snapshot.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Dir returns the configuration directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) watch() {
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	for {
		select {
		case ev, ok := <-s.notify.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			if !strings.HasSuffix(ev.Name, ".yaml") && !strings.HasSuffix(ev.Name, ".yml") {
				continue
			}
			debounce.Reset(400 * time.Millisecond)
		case <-debounce.C:
			if err := s.reload(); err != nil && s.onChange != nil {
				s.onChange(nil)
			}
			debounce.Stop()
			debounce = time.NewTimer(time.Hour)
			debounce.Stop()
		}
	}
}

// Update applies a mutation to the in-memory configuration, persists the
// changed files and re-validates from disk. On any failure the previously
// known-good configuration is restored.
func (s *Store) Update(mutate func(*Config) error) error {
	s.mu.Lock()
	old := s.cur
	cur := s.cur
	s.mu.Unlock()

	if err := mutate(cur); err != nil {
		return err
	}
	if err := SaveUsers(s.dir, cur.Users, cur.AdminToken); err != nil {
		s.mu.Lock()
		s.cur = old
		s.mu.Unlock()
		return err
	}
	if err := SaveGrants(s.dir, cur.Credentials, cur.Grants); err != nil {
		s.mu.Lock()
		s.cur = old
		s.mu.Unlock()
		return err
	}
	if err := SaveRepos(s.dir, cur.WorkspaceRoot, cur.Repos); err != nil {
		s.mu.Lock()
		s.cur = old
		s.mu.Unlock()
		return err
	}
	if err := s.reload(); err != nil {
		s.mu.Lock()
		s.cur = old
		s.mu.Unlock()
		return fmt.Errorf("change rejected by validation: %w", err)
	}
	return nil
}

func (s *Store) reload() error {
	cfg, err := Load(s.dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = cfg
	s.mu.Unlock()
	if s.onChange != nil {
		s.onChange(cfg)
	}
	return nil
}

// Load reads and validates all configuration files from dir.
func Load(dir string) (*Config, error) {
	cfg := &Config{}
	if err := readYAML(filepath.Join(dir, "server.yaml"), &struct {
		Server *Server `yaml:"server"`
	}{&cfg.Server}); err != nil {
		return nil, err
	}
	defaults(&cfg.Server)

	var users struct {
		Users      map[string]User `yaml:"users"`
		AdminToken string          `yaml:"admin_token_hash"`
	}
	if err := readYAML(filepath.Join(dir, "users.yaml"), &users); err != nil {
		return nil, err
	}
	cfg.Users = users.Users
	cfg.AdminToken = users.AdminToken

	if err := readYAML(filepath.Join(dir, "grants.yaml"), &struct {
		Credentials *map[string]Credential `yaml:"credentials"`
		Grants      *[]Grant               `yaml:"grants"`
	}{&cfg.Credentials, &cfg.Grants}); err != nil {
		return nil, err
	}

	if err := readYAML(filepath.Join(dir, "repos.yaml"), &struct {
		WorkspaceRoot *string          `yaml:"workspace_root"`
		Repos         *map[string]Repo `yaml:"repos"`
	}{&cfg.WorkspaceRoot, &cfg.Repos}); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveUsers writes users.yaml (used by the admin console).
func SaveUsers(dir string, users map[string]User, adminToken string) error {
	return writeYAML(filepath.Join(dir, "users.yaml"), map[string]any{
		"users":            users,
		"admin_token_hash": adminToken,
	})
}

// SaveGrants writes grants.yaml (used by the admin console).
func SaveGrants(dir string, creds map[string]Credential, grants []Grant) error {
	return writeYAML(filepath.Join(dir, "grants.yaml"), map[string]any{
		"credentials": creds,
		"grants":      grants,
	})
}

// SaveRepos writes repos.yaml (used by the admin console).
func SaveRepos(dir string, root string, repos map[string]Repo) error {
	return writeYAML(filepath.Join(dir, "repos.yaml"), map[string]any{
		"workspace_root": root,
		"repos":          repos,
	})
}

func defaults(s *Server) {
	if s.Addr == "" {
		s.Addr = ":8443"
	}
	if s.SessionImage == "" {
		s.SessionImage = "git-mcp-session:local"
	}
	if s.SessionTTL == 0 {
		s.SessionTTL = 30 * time.Minute
	}
	if s.ExecTimeout == 0 {
		s.ExecTimeout = 120 * time.Second
	}
	if s.MaxOutputBytes == 0 {
		s.MaxOutputBytes = 1 << 20
	}
	if s.SocketDir == "" {
		s.SocketDir = "/run/git-mcp/agents"
	}
	if s.AuditFile == "" {
		s.AuditFile = "/var/log/git-mcp/audit.jsonl"
	}
	if s.GitHubHost == "" {
		s.GitHubHost = "github.com"
	}
}

// Validate enforces the invariants documented in the design.
func (c *Config) Validate() error {
	if c.WorkspaceRoot == "" || !filepath.IsAbs(c.WorkspaceRoot) {
		return fmt.Errorf("workspace_root must be an absolute path")
	}
	if c.AdminToken == "" || !strings.HasPrefix(c.AdminToken, "$2") {
		return fmt.Errorf("admin_token_hash must be a bcrypt hash")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user must be defined")
	}
	for name, u := range c.Users {
		if !strings.HasPrefix(u.TokenHash, "$2") {
			return fmt.Errorf("user %q: token_hash must be a bcrypt hash", name)
		}
		if u.Name == "" || u.Email == "" {
			return fmt.Errorf("user %q: name and email are required (used for commit attribution)", name)
		}
	}
	if len(c.Repos) == 0 {
		return fmt.Errorf("at least one repo must be defined")
	}
	for id, r := range c.Repos {
		if !strings.Contains(r.GitHub, "/") {
			return fmt.Errorf("repo %q: github must be org/name", id)
		}
		if r.Dir != "" && strings.ContainsAny(r.Dir, "/\\") {
			return fmt.Errorf("repo %q: dir must be a single path element", id)
		}
	}
	for name, cred := range c.Credentials {
		if _, ok := c.Repos[cred.Repo]; !ok {
			return fmt.Errorf("credential %q references unknown repo %q", name, cred.Repo)
		}
		if cred.KeyFile == "" {
			return fmt.Errorf("credential %q: key_file is required", name)
		}
	}
	if len(c.Grants) == 0 {
		return fmt.Errorf("at least one grant must be defined")
	}
	for i, g := range c.Grants {
		if _, ok := c.Users[g.User]; !ok {
			return fmt.Errorf("grant #%d references unknown user %q", i, g.User)
		}
		if _, ok := c.Repos[g.Repo]; !ok {
			return fmt.Errorf("grant #%d references unknown repo %q", i, g.Repo)
		}
		cred, ok := c.Credentials[g.Credential]
		if !ok {
			return fmt.Errorf("grant #%d references unknown credential %q", i, g.Credential)
		}
		if cred.Repo != g.Repo {
			return fmt.Errorf("grant #%d: credential %q is bound to repo %q, not %q", i, g.Credential, cred.Repo, g.Repo)
		}
		if len(g.Actions) == 0 {
			return fmt.Errorf("grant #%d: actions must not be empty", i)
		}
		for _, a := range g.Actions {
			switch a {
			case ActionRead, ActionClone:
			case ActionPush:
				if cred.ReadOnly {
					return fmt.Errorf("grant #%d grants push but credential %q is read-only", i, g.Credential)
				}
			default:
				return fmt.Errorf("grant #%d: unknown action %q", i, a)
			}
		}
	}
	return nil
}

func readYAML(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
