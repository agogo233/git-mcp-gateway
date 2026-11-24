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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Identifier patterns: repo ids are "org/name", everything else
// (workspace dir, credential names) must be a single safe path element.
// These guards also keep admin-supplied names from escaping the workspace
// or key directories ("..", "/", embedded separators).
var (
	repoIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Actions that may be granted on a repository.
const (
	ActionRead  = "read"
	ActionClone = "clone"
	ActionPush  = "push"
)

// Server holds runtime knobs.
type Server struct {
	Addr               string        `yaml:"addr"`          // listen address, e.g. ":8443"
	SessionImage       string        `yaml:"session_image"` // session container image
	SessionTTL         time.Duration `yaml:"session_ttl"`   // idle time before a session container is reaped
	ExecTimeout        time.Duration `yaml:"exec_timeout"`  // per git-command timeout
	MaxOutputBytes     int           `yaml:"max_output_bytes"`
	SocketDir          string        `yaml:"socket_dir"`  // where session agent sockets live
	AuditFile          string        `yaml:"audit_file"`  // JSONL audit sink
	GitHubHost         string        `yaml:"github_host"` // normally github.com
	LogLevel           string        `yaml:"log_level"`
	MaxSessionsPerUser int           `yaml:"max_sessions_per_user"` // active MCP sessions per user
	SessionMemoryMB    int           `yaml:"session_memory_mb"`     // session container memory limit (MB)
	SessionCPUs        float64       `yaml:"session_cpus"`          // session container CPU limit
	SessionPids        int64         `yaml:"session_pids"`          // session container pids limit
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
	writeMu  sync.Mutex // serialises Update so concurrent mutations cannot interleave on disk
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
// changed files and re-validates from disk. The mutation runs on a deep copy
// of the current configuration, so concurrent readers never see a half-mutated
// snapshot and a failed change simply drops the copy. Concurrent Updates are
// serialised by a write lock so their disk writes cannot interleave.
func (s *Store) Update(mutate func(*Config) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	cur := deepCopyConfig(s.cur)
	s.mu.RUnlock()

	if err := mutate(cur); err != nil {
		return err
	}
	if err := saveAll(s.dir, cur); err != nil {
		return err
	}
	if err := s.reload(); err != nil {
		return fmt.Errorf("change rejected by validation: %w", err)
	}
	return nil
}

// saveAll persists all configuration files as one unit: every file is written
// to a temporary name first and only then renamed, so a failure part-way
// through cannot leave a half-updated configuration on disk. If a rename
// fails, the previous file contents are restored.
func saveAll(dir string, c *Config) error {
	files := []struct {
		name string
		v    any
	}{
		{"users.yaml", map[string]any{"users": c.Users, "admin_token_hash": c.AdminToken}},
		{"grants.yaml", map[string]any{"credentials": c.Credentials, "grants": c.Grants}},
		{"repos.yaml", map[string]any{"workspace_root": c.WorkspaceRoot, "repos": c.Repos}},
	}
	old := map[string][]byte{}
	for _, f := range files {
		if b, err := os.ReadFile(filepath.Join(dir, f.name)); err == nil {
			old[f.name] = b
		}
	}
	tmps := make([]string, 0, len(files))
	for _, f := range files {
		data, err := yaml.Marshal(f.v)
		if err != nil {
			for _, t := range tmps {
				_ = os.Remove(t)
			}
			return err
		}
		tmp := filepath.Join(dir, f.name+".tmp")
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			for _, t := range tmps {
				_ = os.Remove(t)
			}
			return err
		}
		tmps = append(tmps, tmp)
	}
	for i, f := range files {
		if err := os.Rename(tmps[i], filepath.Join(dir, f.name)); err != nil {
			for j := 0; j < i; j++ {
				if b, ok := old[files[j].name]; ok {
					_ = os.WriteFile(filepath.Join(dir, files[j].name), b, 0o600)
				}
			}
			for _, t := range tmps {
				_ = os.Remove(t)
			}
			return err
		}
	}
	return nil
}

// deepCopyConfig returns a copy whose maps and slices are independent of the
// original, safe to mutate without holding the store lock.
func deepCopyConfig(c *Config) *Config {
	if c == nil {
		return &Config{}
	}
	out := &Config{
		AdminToken:    c.AdminToken,
		WorkspaceRoot: c.WorkspaceRoot,
		Server:        c.Server,
		Users:         make(map[string]User, len(c.Users)),
		Credentials:   make(map[string]Credential, len(c.Credentials)),
		Repos:         make(map[string]Repo, len(c.Repos)),
		Grants:        make([]Grant, len(c.Grants)),
	}
	for k, v := range c.Users {
		out.Users[k] = v
	}
	for k, v := range c.Credentials {
		out.Credentials[k] = v
	}
	for k, v := range c.Repos {
		out.Repos[k] = v
	}
	copy(out.Grants, c.Grants)
	return out
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
	if s.MaxSessionsPerUser == 0 {
		s.MaxSessionsPerUser = 4
	}
	if s.SessionMemoryMB == 0 {
		s.SessionMemoryMB = 512
	}
	if s.SessionCPUs == 0 {
		s.SessionCPUs = 1
	}
	if s.SessionPids == 0 {
		s.SessionPids = 128
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
	effDirs := map[string]string{}
	for id, r := range c.Repos {
		if !repoIDPattern.MatchString(id) {
			return fmt.Errorf("repo id %q must be org/name using only [A-Za-z0-9._-]", id)
		}
		if !strings.Contains(r.GitHub, "/") {
			return fmt.Errorf("repo %q: github must be org/name", id)
		}
		if !strings.EqualFold(r.GitHub, id) {
			return fmt.Errorf("repo %q: github must match the repo id (the clone URL is derived from the id)", id)
		}
		dir := r.Dir
		if dir == "" {
			_, dir, _ = strings.Cut(id, "/")
		}
		if !namePattern.MatchString(dir) {
			return fmt.Errorf("repo %q: dir must be a single safe path element", id)
		}
		if prev, dup := effDirs[dir]; dup {
			return fmt.Errorf("repo %q: workspace dir %q is already used by repo %q", id, dir, prev)
		}
		effDirs[dir] = id
	}
	for name, cred := range c.Credentials {
		if !namePattern.MatchString(name) {
			return fmt.Errorf("credential name %q must contain only [A-Za-z0-9._-]", name)
		}
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
