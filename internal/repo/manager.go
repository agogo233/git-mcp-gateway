// Package repo manages the persistent workspace directories: repository
// registration, remote consistency checks, health pre-checks and the
// per-repository session mutex.
package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/gittools"
)

// Sentinel errors surfaced to agents with actionable messages.
var (
	ErrNotCloned      = errors.New("workspace directory is not cloned yet")
	ErrLocked         = errors.New("repository is busy in another session")
	ErrRemoteMismatch = errors.New("workspace git remote does not match the registered GitHub repository")
)

// LockState describes who currently holds a repository.
type LockState struct {
	Repo      string    `json:"repo"`
	SessionID string    `json:"session_id"`
	User      string    `json:"user"`
	Acquired  time.Time `json:"acquired"`
	LastUsed  time.Time `json:"last_used"`
}

// Manager guards persistent workspaces and their session locks.
type Manager struct {
	store *config.Store

	mu    sync.Mutex
	locks map[string]*LockState // key: repo id ("org/name")
}

// New builds the manager.
func New(store *config.Store) *Manager {
	return &Manager{store: store, locks: map[string]*LockState{}}
}

// Resolve maps a repo id to its host workspace path.
func (m *Manager) Resolve(repoID string) (config.Repo, string, error) {
	cfg := m.store.Get()
	r, ok := cfg.Repos[repoID]
	if !ok {
		return config.Repo{}, "", fmt.Errorf("unknown repo %q", repoID)
	}
	dir, err := cfg.DirFor(repoID)
	if err != nil {
		return config.Repo{}, "", err
	}
	return r, filepath.Join(cfg.WorkspaceRoot, dir), nil
}

// Precheck validates the persistent workspace before a session container is
// created: registered path, cloned state, remote consistency and stale git
// locks. It never mutates the workspace.
func (m *Manager) Precheck(repoID string) error {
	_, path, err := m.Resolve(repoID)
	if err != nil {
		return err
	}
	cfg := m.store.Get()
	r := cfg.Repos[repoID]

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("workspace directory missing: %w", err)
	}
	gitDir := filepath.Join(path, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return ErrNotCloned
	}
	url, ok := readOriginURL(gitDir)
	if !ok {
		return fmt.Errorf("no origin remote configured in %s", gitDir)
	}
	if !remoteMatches(url, cfg.Server.GitHubHost, r.GitHub) {
		return fmt.Errorf("%w: origin=%s want %s", ErrRemoteMismatch, sanitizeURL(url), r.GitHub)
	}
	if _, err := os.Stat(filepath.Join(gitDir, "index.lock")); err == nil {
		return fmt.Errorf("stale .git/index.lock present; run the workspace repair tool first")
	}
	return nil
}

// EnsureDir creates the workspace subdirectory (gateway runs with the
// gitmcp uid and holds a read-write mount of the workspace root).
func (m *Manager) EnsureDir(repoID string) (string, error) {
	_, path, err := m.Resolve(repoID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// FixWorkspace removes stale git lock files so the next session can proceed.
func (m *Manager) FixWorkspace(repoID string) ([]string, error) {
	_, path, err := m.Resolve(repoID)
	if err != nil {
		return nil, err
	}
	gitDir := filepath.Join(path, ".git")
	var removed []string
	candidates := []string{
		filepath.Join(gitDir, "index.lock"),
		filepath.Join(gitDir, "HEAD.lock"),
		filepath.Join(gitDir, "config.lock"),
	}
	for _, c := range candidates {
		if err := os.Remove(c); err == nil {
			removed = append(removed, filepath.Base(c))
		}
	}
	return removed, nil
}

// ResetWorkspace force-resets the persistent workspace to the last committed
// state, discarding uncommitted changes; with clean it also removes untracked
// files. It is the admin console's only sanctioned big reset: it refuses to
// run while a session holds the repository lock and cleans stale git lock
// files first so the reset cannot fail on a dead process's leftovers.
func (m *Manager) ResetWorkspace(repoID string, clean bool) ([]string, error) {
	_, path, err := m.Resolve(repoID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err != nil {
		return nil, ErrNotCloned
	}
	// Occupy the repository lock for the whole reset, so no session can
	// start working in the workspace while it is being reset.
	if err := m.TryLock(repoID, "admin-reset", "admin"); err != nil {
		return nil, fmt.Errorf("%w: unlock the session before resetting the workspace", ErrLocked)
	}
	defer m.Release(repoID, "admin-reset")
	if _, err := m.FixWorkspace(repoID); err != nil {
		return nil, err
	}
	cmds := [][]string{
		{"git", "-C", path, "reset", "--hard"},
	}
	if clean {
		cmds = append(cmds, []string{"git", "-C", path, "clean", "-fd"})
	}
	var out []string
	for _, c := range cmds {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		data, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return out, fmt.Errorf("git %s failed: %s", strings.Join(c[2:], " "), strings.TrimSpace(string(data)))
		}
		out = append(out, strings.TrimSpace(string(data)))
	}
	return out, nil
}

// TryLock acquires the repository mutex for a session. It fails immediately
// when another live session holds the repository.
func (m *Manager) TryLock(repoID, sessionID, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.locks[repoID]; ok && l.SessionID != sessionID {
		return fmt.Errorf("%w: held by session %s (user %s) since %s",
			ErrLocked, l.SessionID, l.User, l.Acquired.Format(time.RFC3339))
	}
	now := time.Now()
	if l, ok := m.locks[repoID]; ok && l.SessionID == sessionID {
		l.LastUsed = now
		return nil
	}
	m.locks[repoID] = &LockState{Repo: repoID, SessionID: sessionID, User: user, Acquired: now, LastUsed: now}
	return nil
}

// Touch refreshes the last-used timestamp of a held lock.
func (m *Manager) Touch(repoID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.locks[repoID]; ok {
		l.LastUsed = time.Now()
	}
}

// Release drops the lock if it belongs to the given session.
func (m *Manager) Release(repoID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.locks[repoID]; ok && l.SessionID == sessionID {
		delete(m.locks, repoID)
	}
}

// ReleaseSession drops every lock held by a session.
func (m *Manager) ReleaseSession(sessionID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var freed []string
	for k, l := range m.locks {
		if l.SessionID == sessionID {
			delete(m.locks, k)
			freed = append(freed, k)
		}
	}
	return freed
}

// Restore re-registers a lock after a gateway restart (self-healing).
func (m *Manager) Restore(repoID, sessionID, user string, acquired, lastUsed time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locks[repoID] = &LockState{Repo: repoID, SessionID: sessionID, User: user, Acquired: acquired, LastUsed: lastUsed}
}

// Snapshot lists current locks (admin console).
func (m *Manager) Snapshot() []LockState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LockState, 0, len(m.locks))
	for _, l := range m.locks {
		out = append(out, *l)
	}
	return out
}

// Expire returns locks idle for longer than ttl (reaper input).
func (m *Manager) Expire(ttl time.Duration) []LockState {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LockState
	for _, l := range m.locks {
		if time.Since(l.LastUsed) > ttl {
			out = append(out, *l)
		}
	}
	return out
}

// readOriginURL extracts the origin URL from a plain .git/config file without
// pulling in an INI dependency.
func readOriginURL(gitDir string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(gitDir, "config"))
	if err != nil {
		return "", false
	}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section == `remote "origin"` {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "url" {
				return strings.TrimSpace(v), true
			}
		}
	}
	return "", false
}

// remoteMatches checks that a git remote URL points at the expected GitHub
// repository over SSH or HTTPS. The URL authority is compared exactly (no
// substring matching), so look-alike hosts cannot pass the check.
func remoteMatches(url, host, repo string) bool {
	uhost, upath, ok := gittools.ParseGitURL(url)
	if !ok {
		return false
	}
	return strings.EqualFold(uhost, host) && strings.EqualFold(upath, repo)
}

func sanitizeURL(url string) string {
	if i := strings.Index(url, "@"); i >= 0 {
		return url[:i] + "@[redacted]"
	}
	return url
}
