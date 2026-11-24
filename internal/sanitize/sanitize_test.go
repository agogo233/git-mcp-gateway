package sanitize

import "strings"

import "testing"

func TestCleanPrivateKeys(t *testing.T) {
	in := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	if out := Clean(in); strings.Contains(out, "b3BlbnNzaC1rZXktdjE") {
		t.Fatalf("private key material leaked: %s", out)
	}
}

func TestCleanTokens(t *testing.T) {
	cases := map[string]string{
		"ghp_Abcdefghijklmnopqrstuvwx":             "[github token removed]",
		"github_pat_ABCDEFGHIJKLMNOPQRST_token":    "[github token removed]",
		"token=abcdef0123456789abcdef0123456789":   "token=[redacted]",
		"https://user:secret@github.com/org/repo":  "https://[cred]@github.com/org/repo",
		"https://abcd1234efgh@github.com/org/repo": "https://[cred]@github.com/org/repo",
		"AGE-SECRET-KEY-1ABCDEFGHJKLMNPQRSTUVWXYZ": "[age key removed]",
	}
	for in, must := range cases {
		out := Clean(in)
		if !strings.Contains(out, must) {
			t.Fatalf("Clean(%q) = %q, want substring %q", in, out, must)
		}
	}
}

func TestCleanKeepsNormalGitOutput(t *testing.T) {
	in := "On branch main\nYour branch is up to date with 'origin/main'.\nnothing to commit, working tree clean"
	if out := Clean(in); out != in {
		t.Fatalf("Clean altered normal output: %q", out)
	}
	// a URL whose path merely contains "@" is not an embedded credential
	url := "https://github.com/org/repo@v1/issues"
	if out := Clean(url); out != url {
		t.Fatalf("Clean altered a URL without embedded credentials: %q", out)
	}
}
