package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(dir, name, content string) {
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		panic(err)
	}
}

func baseConfig(users, grants, repos string) (string, func()) {
	dir, err := os.MkdirTemp("", "gmcp-cfg")
	if err != nil {
		panic(err)
	}
	write(dir, "server.yaml", "server:\n  addr: \":8443\"\n  session_image: git-mcp-session:local\n")
	write(dir, "users.yaml", users)
	write(dir, "grants.yaml", grants)
	write(dir, "repos.yaml", repos)
	return dir, func() { os.RemoveAll(dir) }
}

const validUsers = `users:
  alice:
    token_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    name: Alice
    email: alice@corp.com
admin_token_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`

const validGrants = `credentials:
  key-alice:
    repo: org/proj1
    readonly: false
    key_file: /keys/key-alice.age
grants:
  - user: alice
    repo: org/proj1
    actions: [read, clone, push]
    credential: key-alice
`

const validRepos = `workspace_root: /srv/workspaces
repos:
  org/proj1:
    github: org/proj1
`

func TestLoadValid(t *testing.T) {
	dir, clean := baseConfig(validUsers, validGrants, validRepos)
	defer clean()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Server.Addr != ":8443" {
		t.Fatalf("addr default not applied")
	}
	path, err := cfg.RepoPath("org/proj1")
	if err != nil || path != "/srv/workspaces/proj1" {
		t.Fatalf("repo path = %q, err=%v", path, err)
	}
}

func TestLoadRejectsReadOnlyPush(t *testing.T) {
	dir, clean := baseConfig(validUsers, `credentials:
  key-alice:
    repo: org/proj1
    readonly: true
    key_file: /keys/k.age
grants:
  - user: alice
    repo: org/proj1
    actions: [push]
    credential: key-alice
`, validRepos)
	defer clean()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected validation error for push on read-only credential")
	}
}

func TestLoadRejectsUnknownCredential(t *testing.T) {
	dir, clean := baseConfig(validUsers, `credentials: {}
grants:
  - user: alice
    repo: org/proj1
    actions: [read]
    credential: nope
`, validRepos)
	defer clean()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected validation error for unknown credential")
	}
}

func TestLoadRejectsGithubMismatch(t *testing.T) {
	dir, clean := baseConfig(validUsers, validGrants, `workspace_root: /srv/workspaces
repos:
  org/proj1:
    github: other/name
`)
	defer clean()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected validation error when github does not match the repo id")
	}
}

func TestLoadRejectsDuplicateWorkspaceDir(t *testing.T) {
	for _, repos := range []string{
		// default-derived conflict: both repos derive the dir "proj1"
		`workspace_root: /srv/workspaces
repos:
  org/proj1:
    github: org/proj1
  other/proj1:
    github: other/proj1
`,
		// explicit conflict: two repos declare the same dir
		`workspace_root: /srv/workspaces
repos:
  org/proj1:
    github: org/proj1
  org/proj2:
    github: org/proj2
    dir: proj1
`,
	} {
		dir, clean := baseConfig(validUsers, validGrants, repos)
		if _, err := Load(dir); err == nil {
			t.Fatalf("expected validation error for duplicate workspace dir:\n%s", repos)
		}
		clean()
	}
}

func TestServerDefaults(t *testing.T) {
	dir, clean := baseConfig(validUsers, validGrants, validRepos)
	defer clean()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MaxSessionsPerUser != 4 {
		t.Fatalf("MaxSessionsPerUser default = %d, want 4", cfg.Server.MaxSessionsPerUser)
	}
	if cfg.Server.SessionMemoryMB != 512 {
		t.Fatalf("SessionMemoryMB default = %d, want 512", cfg.Server.SessionMemoryMB)
	}
	if cfg.Server.SessionCPUs != 1 {
		t.Fatalf("SessionCPUs default = %v, want 1", cfg.Server.SessionCPUs)
	}
	if cfg.Server.SessionPids != 128 {
		t.Fatalf("SessionPids default = %d, want 128", cfg.Server.SessionPids)
	}
}

func TestLoadRejectsBadRepoDir(t *testing.T) {
	dir, clean := baseConfig(validUsers, validGrants, `workspace_root: /srv/workspaces
repos:
  org/proj1:
    github: org/proj1
    dir: "a/b"
`)
	defer clean()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected validation error for dir with slash")
	}
}

func TestLoadRejectsDotDotDir(t *testing.T) {
	for _, d := range []string{"..", ".", ".git"} {
		dir, clean := baseConfig(validUsers, validGrants, "workspace_root: /srv/workspaces\nrepos:\n  org/proj1:\n    github: org/proj1\n    dir: "+d+"\n")
		if _, err := Load(dir); err == nil {
			t.Fatalf("expected validation error for dir %q", d)
		}
		clean()
	}
}

func TestLoadRejectsBadRepoID(t *testing.T) {
	for _, id := range []string{"org/../x", "org//x", "../org", "org/proj1 "} {
		dir, clean := baseConfig(validUsers, validGrants, "workspace_root: /srv/workspaces\nrepos:\n  \""+id+"\":\n    github: org/proj1\n")
		if _, err := Load(dir); err == nil {
			t.Fatalf("expected validation error for repo id %q", id)
		}
		clean()
	}
}

func TestLoadRejectsBadCredentialName(t *testing.T) {
	dir, clean := baseConfig(validUsers, `credentials:
  "a/b":
    repo: org/proj1
    readonly: false
    key_file: /keys/k.age
grants:
  - user: alice
    repo: org/proj1
    actions: [read]
    credential: a/b
`, validRepos)
	defer clean()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected validation error for credential name with slash")
	}
}

func TestUpdateDeepCopyIsolation(t *testing.T) {
	dir, clean := baseConfig(validUsers, validGrants, validRepos)
	defer clean()
	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// mutate on a copy must not leak into what readers see
	if err := store.Update(func(c *Config) error {
		c.Users["ghost"] = User{TokenHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", Name: "G", Email: "g@c"}
		return nil
	}); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if _, ok := store.Get().Users["ghost"]; !ok {
		t.Fatal("expected update to be visible after successful reload")
	}
	// a failing mutation must not corrupt the live config
	if err := store.Update(func(c *Config) error {
		c.Grants = nil
		return nil
	}); err == nil {
		t.Fatal("expected validation failure when grants become empty")
	}
	if len(store.Get().Grants) == 0 {
		t.Fatal("live config must keep the previous grants after a rejected change")
	}
}
