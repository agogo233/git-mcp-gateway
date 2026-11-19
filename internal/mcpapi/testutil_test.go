package mcpapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/repo"
	"golang.org/x/crypto/bcrypt"
)

// testTokens carries the plaintext credentials used by the test store.
type testTokens struct {
	alice string
	bob   string
	admin string
}

// newTestServer builds an mcpapi.Server backed by a real hot-reload store with
// two users (alice: read/clone/push, bob: read/clone) and one repo. The
// docker session manager and agent pool are intentionally absent: tests that
// exercise authorization failures never reach them.
func newTestServer(t *testing.T) (*Server, testTokens) {
	t.Helper()
	tokens := testTokens{alice: "alice-tok", bob: "bob-tok", admin: "admin-tok"}
	dir := t.TempDir()

	hash := func(s string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	files := map[string]string{
		"server.yaml": "server:\n  addr: \":8443\"\n  session_image: git-mcp-session:local\n  socket_dir: " +
			filepath.Join(t.TempDir(), "agents") + "\n  audit_file: " + filepath.Join(t.TempDir(), "audit.jsonl") + "\n",
		"users.yaml":  "users:\n  alice:\n    token_hash: \"" + hash(tokens.alice) + "\"\n    name: Alice\n    email: alice@corp.com\n  bob:\n    token_hash: \"" + hash(tokens.bob) + "\"\n    name: Bob\n    email: bob@corp.com\nadmin_token_hash: \"" + hash(tokens.admin) + "\"\n",
		"grants.yaml": "credentials:\n  key-alice:\n    repo: org/proj1\n    readonly: false\n    key_file: /keys/k.age\ngrants:\n  - user: alice\n    repo: org/proj1\n    actions: [read, clone, push]\n    credential: key-alice\n  - user: bob\n    repo: org/proj1\n    actions: [read, clone]\n    credential: key-alice\n",
		"repos.yaml":  "workspace_root: " + filepath.Join(t.TempDir(), "ws") + "\nrepos:\n  org/proj1:\n    github: org/proj1\n",
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
	auditL, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditL.Close() })
	authn := auth.New(store)
	repos := repo.New(store)
	return New(store, authn, auditL, repos, nil, nil, "test"), tokens
}
