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
