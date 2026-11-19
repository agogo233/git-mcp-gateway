package gittools

import (
	"testing"

	"github.com/local/git-mcp-gateway/internal/config"
)

func TestCheckRunArgs(t *testing.T) {
	allowed := [][]string{
		{"git", "log", "--oneline", "-n", "5"},
		{"git", "status"},
		{"git", "diff", "--staged"},
		{"git", "push", "origin", "feature/x"},
		{"git", "branch", "new-branch"},
		{"git", "remote", "-v"},
		{"git", "remote", "get-url", "origin"},
		{"git", "fetch", "--prune"},
		{"git", "fetch", "origin"},
	}
	for _, a := range allowed {
		if err := CheckRunArgs(a); err != nil {
			t.Fatalf("expected %v allowed, got %v", a, err)
		}
	}
	denied := [][]string{
		{"git", "push", "--force", "origin", "main"},
		{"git", "push", "origin", ":main"},
		{"git", "push", "origin", "+main"},
		{"git", "push", "--force-with-lease", "origin", "main"},
		{"git", "push", "--force-with-lease=main:abc", "origin", "main"},
		{"git", "push", "--mirror"},
		{"git", "fetch", "+refs/heads/main:refs/remotes/origin/main"},
		{"git", "remote", "set-url", "origin", "git@evil.com:x/y.git"},
		{"git", "remote", "add", "upstream", "git@github.com:o/r.git"},
		{"git", "remote", "rename", "origin", "upstream"},
		{"git", "reset", "--hard", "HEAD~1"},
		{"git", "commit", "--amend"},
		{"git", "clean", "-fd"},
		{"git", "config", "user.name", "evil"},
		{"git", "submodule", "update", "--init"},
		{"ls", "-la"},
		{"git"},
	}
	for _, a := range denied {
		if err := CheckRunArgs(a); err == nil {
			t.Fatalf("expected %v denied", a)
		}
	}
}

func TestRequiredAction(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"git", "log", "--oneline"}, config.ActionRead},
		{[]string{"git", "status"}, config.ActionRead},
		{[]string{"git", "diff", "--staged"}, config.ActionRead},
		{[]string{"git", "branch", "-a"}, config.ActionRead},
		{[]string{"git", "remote", "-v"}, config.ActionRead},
		{[]string{"git", "pull", "--ff-only"}, config.ActionClone},
		{[]string{"git", "fetch", "--all"}, config.ActionClone},
		{[]string{"git", "checkout", "main"}, config.ActionClone},
		{[]string{"git", "switch", "dev"}, config.ActionClone},
		{[]string{"git", "add", "-A"}, config.ActionPush},
		{[]string{"git", "commit", "-m", "x"}, config.ActionPush},
		{[]string{"git", "push", "origin", "main"}, config.ActionPush},
		{[]string{"git", "merge", "feature"}, config.ActionPush},
		{[]string{"git", "rebase", "main"}, config.ActionPush},
		{[]string{"git", "cherry-pick", "abc123"}, config.ActionPush},
		{[]string{"git", "revert", "abc123"}, config.ActionPush},
		{[]string{"git", "stash", "push"}, config.ActionPush},
		{[]string{"git", "restore", "src/x"}, config.ActionClone},
		// unknown/missing subcommand defaults to read (safety net)
		{[]string{"git"}, config.ActionRead},
		{[]string{"git", "unknown-sub"}, config.ActionRead},
	}
	for _, c := range cases {
		if got := RequiredAction(c.args); got != c.want {
			t.Fatalf("RequiredAction(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestValidateRefName(t *testing.T) {
	if err := ValidateRefName("feature/x"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "-x", "a b", "a..b", "a:b"} {
		if err := ValidateRefName(bad); err == nil {
			t.Fatalf("expected %q denied", bad)
		}
	}
}

func TestValidateRelPath(t *testing.T) {
	if err := ValidateRelPath("src/main.go"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/etc/passwd", "../secret"} {
		if err := ValidateRelPath(bad); err == nil {
			t.Fatalf("expected %q denied", bad)
		}
	}
}
