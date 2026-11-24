package mcpapi

import (
	"context"
	"strings"
	"testing"
)

func TestRunGitRequiresPushForWriteSubcommands(t *testing.T) {
	srv, _ := newTestServer(t)

	def, ok := srv.toolByName("run_git")
	if !ok {
		t.Fatal("run_git tool not registered")
	}

	// bob has only read+clone: push must be refused before any docker work
	ctx := context.Background()
	bob := &callCtx{s: srv, sess: &mcpSession{ID: "sess-bob", User: "bob"}}
	_, err := def.Run(ctx, bob, map[string]any{
		"repo": "org/proj1",
		"args": []any{"git", "push", "origin", "main"},
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied for push, got %v", err)
	}

	// write-style subcommands (commit/add) are refused too
	for _, sub := range []string{"commit", "add", "merge", "stash"} {
		_, err := def.Run(ctx, bob, map[string]any{
			"repo": "org/proj1",
			"args": []any{"git", sub, "-m", "x"},
		})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied for %q, got %v", sub, err)
		}
	}
}

func TestLocalReadTools(t *testing.T) {
	srv, _ := newTestServer(t)

	// local-inspection tools are marked local-read
	for _, name := range []string{"git_status", "git_diff", "git_log", "git_branch_list"} {
		def, ok := srv.toolByName(name)
		if !ok {
			t.Fatalf("tool %s not registered", name)
		}
		if def.LocalRead == nil || !def.LocalRead(map[string]any{"repo": "org/proj1"}) {
			t.Fatalf("tool %s must be marked local-read", name)
		}
	}

	// run_git is local-read only for read-style subcommands
	def, ok := srv.toolByName("run_git")
	if !ok {
		t.Fatal("run_git tool not registered")
	}
	if def.LocalRead == nil {
		t.Fatal("run_git must carry a local-read predicate")
	}
	if !def.LocalRead(map[string]any{"args": []any{"git", "log", "--oneline"}}) {
		t.Fatal("git log through run_git must be local-read")
	}
	if def.LocalRead(map[string]any{"args": []any{"git", "push", "origin", "main"}}) {
		t.Fatal("git push through run_git must not be local-read")
	}
}
