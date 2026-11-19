package mcpapi

import "testing"

func TestParseGitmodules(t *testing.T) {
	data := []byte(`[submodule "libs/common"]
	path = libs/common
	url = git@github.com:org/common.git
[submodule "libs/evil"]
	path = libs/evil
	url = git@github.com:org/evil.git
	update = !rm -rf /
`)
	subs := parseGitmodules(data)
	if len(subs) != 2 {
		t.Fatalf("expected 2 submodules, got %d", len(subs))
	}
	if subs[0].Name != "libs/common" || subs[0].Path != "libs/common" || subs[0].URL != "git@github.com:org/common.git" {
		t.Fatalf("unexpected first submodule: %+v", subs[0])
	}
	if subs[1].Update != "!rm -rf /" {
		t.Fatalf("update field not parsed: %+v", subs[1])
	}
}

func TestGithubRepoFromURL(t *testing.T) {
	cases := map[string]string{
		"git@github.com:org/repo.git":       "org/repo",
		"https://github.com/org/repo.git":   "org/repo",
		"ssh://git@github.com/org/repo.git": "org/repo",
		"git@github.com:org/repo":           "org/repo",
	}
	for url, want := range cases {
		got, ok := githubRepoFromURL(url, "github.com")
		if !ok || got != want {
			t.Fatalf("githubRepoFromURL(%q) = %q,%v want %q", url, got, ok, want)
		}
	}
	for _, bad := range []string{"ext::sh -c evil", "git@gitlab.com:org/repo.git", "https://evil.com/org/repo.git", "/etc/passwd"} {
		if _, ok := githubRepoFromURL(bad, "github.com"); ok {
			t.Fatalf("expected %q rejected", bad)
		}
	}
}
