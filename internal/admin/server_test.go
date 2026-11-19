package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/repo"
	"golang.org/x/crypto/bcrypt"
)

// newTestAdmin builds an admin.Server over a real hot-reload store.
func newTestAdmin(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	hash := func(s string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	keyFile := filepath.Join(t.TempDir(), "key-alice.age")
	files := map[string]string{
		"server.yaml": "server:\n  addr: \":8443\"\n  session_image: git-mcp-session:local\n  socket_dir: " +
			filepath.Join(t.TempDir(), "agents") + "\n  audit_file: " + filepath.Join(t.TempDir(), "audit.jsonl") + "\n",
		"users.yaml":  "users:\n  alice:\n    token_hash: \"" + hash("tok") + "\"\n    name: Alice\n    email: alice@corp.com\nadmin_token_hash: \"" + hash("admin") + "\"\n",
		"grants.yaml": "credentials:\n  key-alice:\n    repo: org/proj1\n    readonly: false\n    key_file: " + keyFile + "\n  key-bob:\n    repo: org/proj2\n    readonly: false\n    key_file: " + filepath.Join(t.TempDir(), "key-bob.age") + "\ngrants:\n  - user: alice\n    repo: org/proj1\n    actions: [read, clone, push]\n    credential: key-alice\n  - user: alice\n    repo: org/proj2\n    actions: [read]\n    credential: key-bob\n",
		"repos.yaml":  "workspace_root: " + filepath.Join(t.TempDir(), "ws") + "\nrepos:\n  org/proj1:\n    github: org/proj1\n  org/proj2:\n    github: org/proj2\n",
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
	return &Server{
		Store: store, Auth: auth.New(store), Audit: auditL,
		Repos: repo.New(store), Version: "test",
	}
}

func TestCreateCredentialRejectsBadName(t *testing.T) {
	s := newTestAdmin(t)
	for _, name := range []string{"../evil", "a/b", "a\\b", ".hidden"} {
		body := strings.NewReader(`{"name":"` + name + `","repo":"org/proj1"}`)
		req := httptest.NewRequest("POST", "/admin/api/credentials", body)
		rec := httptest.NewRecorder()
		s.createCredential(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for name %q, got %d", name, rec.Code)
		}
	}
}

func TestDeleteCredentialRemovesKeyFile(t *testing.T) {
	s := newTestAdmin(t)
	keyFile := ""
	cfg := s.Store.Get()
	for _, c := range cfg.Credentials {
		keyFile = c.KeyFile
	}
	if keyFile == "" {
		t.Fatal("test config must define a key file")
	}
	if err := os.WriteFile(keyFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/admin/api/credentials/key-alice", nil)
	rec := httptest.NewRecorder()
	s.deleteCredential(rec, req, "key-alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete failed: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("key file should be removed, stat err=%v", err)
	}
	if _, ok := s.Store.Get().Credentials["key-alice"]; ok {
		t.Fatal("credential should be gone from config")
	}
}

func TestUpsertRepoRejectsBadID(t *testing.T) {
	s := newTestAdmin(t)
	req := httptest.NewRequest("POST", "/admin/api/repos",
		strings.NewReader(`{"id":"../x","github":"org/proj1"}`))
	rec := httptest.NewRecorder()
	s.upsertRepo(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad repo id, got %d: %s", rec.Code, rec.Body.String())
	}
}
