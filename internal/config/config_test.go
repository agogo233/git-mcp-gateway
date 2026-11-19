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
