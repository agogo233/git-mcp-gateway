package repo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/local/git-mcp-gateway/internal/config"
)

func TestRemoteMatches(t *testing.T) {
	cases := []struct {
		url, host, repo string
		want            bool
	}{
		{"git@github.com:org/proj1.git", "github.com", "org/proj1", true},
		{"https://github.com/org/proj1.git", "github.com", "org/proj1", true},
		{"ssh://git@github.com/org/proj1.git", "github.com", "org/proj1", true},
		{"git@github.com:org/other.git", "github.com", "org/proj1", false},
		{"git@gitlab.com:org/proj1.git", "github.com", "org/proj1", false},
		{"git@evil-github.com:org/proj1.git", "github.com", "org/proj1", false},
		{"https://github.com.evil.com/org/proj1.git", "github.com", "org/proj1", false},
		{"git@github.com:org/proj1", "github.com", "org/proj1", true},
	}
	for _, c := range cases {
		if got := remoteMatches(c.url, c.host, c.repo); got != c.want {
			t.Fatalf("remoteMatches(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

// setup writes a real configuration directory and returns a hot-reload store,
// exercising the production loading path.
func setup(t *testing.T, workspaceRoot string) *config.Store {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"server.yaml": "server:\n  addr: \":8443\"\n  session_image: git-mcp-session:local\n  socket_dir: " +
			filepath.Join(t.TempDir(), "agents") + "\n  audit_file: " + filepath.Join(t.TempDir(), "audit.jsonl") + "\n",
		"users.yaml": `users:
  alice:
    token_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    name: Alice
    email: alice@corp.com
admin_token_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`,
		"grants.yaml": `credentials:
  key-alice:
    repo: org/proj1
    readonly: false
    key_file: /keys/key-alice.age
grants:
  - user: alice
    repo: org/proj1
    actions: [read, clone, push]
    credential: key-alice
`,
		"repos.yaml": "workspace_root: " + workspaceRoot + "\nrepos:\n  org/proj1:\n    github: org/proj1\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := config.NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPrecheckAndLocks(t *testing.T) {
	repoID := "org/proj1"
	ws := t.TempDir()
	repoDir := filepath.Join(ws, "proj1")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := setup(t, ws)
	m := New(store)

	// not cloned yet
	if err := m.Precheck(repoID); err != ErrNotCloned {
		t.Fatalf("expected ErrNotCloned, got %v", err)
	}
	// fake a clone with a matching remote
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = git@github.com:org/proj1.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Precheck(repoID); err != nil {
		t.Fatalf("precheck after clone: %v", err)
	}

	// locks: first session acquires, second is refused
	if err := m.TryLock(repoID, "s1", "alice"); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := m.TryLock(repoID, "s2", "bob"); err == nil {
		t.Fatal("expected second lock to fail")
	}
	// same session re-locks fine
	if err := m.TryLock(repoID, "s1", "alice"); err != nil {
		t.Fatalf("re-lock same session: %v", err)
	}
	// release only drops the owner's lock
	m.Release(repoID, "s2")
	if len(m.Snapshot()) != 1 {
		t.Fatal("lock should still be held by s1")
	}
	m.Release(repoID, "s1")
	if len(m.Snapshot()) != 0 {
		t.Fatal("lock should be free")
	}
}

func TestExpire(t *testing.T) {
	repoID := "org/proj1"
	ws := t.TempDir()
	m := New(setup(t, ws))
	if err := m.TryLock(repoID, "s1", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := m.Expire(time.Hour); len(got) != 0 {
		t.Fatal("fresh lock must not expire")
	}
	m.mu.Lock()
	m.locks[repoID].LastUsed = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()
	if got := m.Expire(time.Hour); len(got) != 1 {
		t.Fatal("expected expired lock")
	}
}

func TestPrecheckRejectsRemoteMismatch(t *testing.T) {
	repoID := "org/proj1"
	ws := t.TempDir()
	repoDir := filepath.Join(ws, "proj1")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = git@github.com:org/other.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(setup(t, ws))
	if err := m.Precheck(repoID); !errors.Is(err, ErrRemoteMismatch) {
		t.Fatalf("expected ErrRemoteMismatch, got %v", err)
	}
}

func TestResetWorkspace(t *testing.T) {
	repoID := "org/proj1"
	ws := t.TempDir()
	repoDir := filepath.Join(ws, "proj1")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.CommandContext(context.Background(), args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("git", "init")
	run("git", "config", "user.name", "Tester")
	run("git", "config", "user.email", "tester@test.com")
	if err := os.WriteFile(filepath.Join(repoDir, "file.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "file.txt")
	run("git", "commit", "-m", "init")

	// dirty the workspace: modify a tracked file and add an untracked one
	if err := os.WriteFile(filepath.Join(repoDir, "file.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "junk.txt"), []byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := New(setup(t, ws))

	// reset --hard restores tracked files but keeps untracked files
	if _, err := m.ResetWorkspace(repoID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(repoDir, "file.txt")); string(got) != "tracked\n" {
		t.Fatalf("tracked file not restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "junk.txt")); err != nil {
		t.Fatal("untracked file must survive a reset without clean")
	}

	// reset with clean removes untracked files
	if _, err := m.ResetWorkspace(repoID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "junk.txt")); !os.IsNotExist(err) {
		t.Fatal("clean should remove untracked files")
	}

	// refused while a session holds the lock
	if err := m.TryLock(repoID, "s1", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResetWorkspace(repoID, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	m.Release(repoID, "s1")

	// refused when the workspace is not cloned
	if _, err := New(setup(t, t.TempDir())).ResetWorkspace(repoID, false); !errors.Is(err, ErrNotCloned) {
		t.Fatalf("expected ErrNotCloned, got %v", err)
	}
}
