package gittools

import "testing"

func TestParseGitURL(t *testing.T) {
	cases := []struct {
		raw, host, path string
		ok              bool
	}{
		{"git@github.com:org/repo.git", "github.com", "org/repo", true},
		{"git@github.com:org/repo", "github.com", "org/repo", true},
		{"https://github.com/org/repo.git", "github.com", "org/repo", true},
		{"https://github.com/org/repo", "github.com", "org/repo", true},
		{"ssh://git@github.com/org/repo.git", "github.com", "org/repo", true},
		{"ssh://git@github.com:22/org/repo.git", "github.com", "org/repo", true},
		{"git@gitlab.com:org/repo.git", "gitlab.com", "org/repo", true},
		// look-alike hosts must never be extracted as the real one
		{"git@evil-github.com:org/repo.git", "evil-github.com", "org/repo", true},
		{"https://github.com.evil.com/org/repo.git", "github.com.evil.com", "org/repo", true},
		// malformed / non-URL inputs are rejected
		{"", "", "", false},
		{"git@github.com", "", "", false},
		{"/etc/passwd", "", "", false},
		{"ext::sh -c evil", "", "", false},
		{"git@github.com:/org/repo", "", "", false},
	}
	for _, c := range cases {
		host, path, ok := ParseGitURL(c.raw)
		if ok != c.ok || host != c.host || path != c.path {
			t.Fatalf("ParseGitURL(%q) = (%q,%q,%v), want (%q,%q,%v)", c.raw, host, path, ok, c.host, c.path, c.ok)
		}
	}
}
