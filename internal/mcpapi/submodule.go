package mcpapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// submodule is one entry of a .gitmodules file.
type submodule struct {
	Name   string
	Path   string
	URL    string
	Update string
}

// parseGitmodules parses the INI-style .gitmodules content.
func parseGitmodules(data []byte) []submodule {
	var out []submodule
	section := ""
	cur := -1
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			if strings.HasPrefix(section, `submodule `) {
				out = append(out, submodule{Name: strings.Trim(strings.TrimPrefix(section, `submodule`), ` "`)})
				cur = len(out) - 1
			} else {
				cur = -1
			}
			continue
		}
		if cur < 0 {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "path":
			out[cur].Path = v
		case "url":
			out[cur].URL = v
		case "update":
			out[cur].Update = v
		}
	}
	return out
}

// resolveSubmodules validates .gitmodules against the authorization table and
// returns the credential names required to fetch every submodule. The check
// runs before every git operation on a cloned workspace, so a malicious
// .gitmodules can never reach the execution container.
func (s *Server) resolveSubmodules(user, repoPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(repoPath, ".gitmodules"))
	if err != nil {
		return nil, nil // no submodules — nothing to do
	}
	cfg := s.Store.Get()
	host := cfg.Server.GitHubHost
	var credsNeeded []string
	seen := map[string]bool{}
	for _, sm := range parseGitmodules(data) {
		if strings.HasPrefix(sm.Update, "!") {
			return nil, fmt.Errorf("submodule %q: custom update command is not allowed", sm.Name)
		}
		if strings.Contains(sm.URL, "ext::") || strings.HasPrefix(sm.URL, "!") {
			return nil, fmt.Errorf("submodule %q: url %q is not allowed", sm.Name, sm.URL)
		}
		if strings.Contains(sm.Path, "..") || strings.HasPrefix(sm.Path, "/") {
			return nil, fmt.Errorf("submodule %q: path %q is not allowed", sm.Name, sm.Path)
		}
		repoID, ok := githubRepoFromURL(sm.URL, host)
		if !ok {
			return nil, fmt.Errorf("submodule %q: url %q is not a %s repository", sm.Name, sm.URL, host)
		}
		if _, ok := cfg.Repos[repoID]; !ok {
			return nil, fmt.Errorf("submodule %q: repository %s is not registered with the gateway", sm.Name, repoID)
		}
		grant, ok := cfg.GrantFor(user, repoID)
		if !ok || !(grant.HasAction("read") || grant.HasAction("clone")) {
			return nil, fmt.Errorf("submodule %q: you have no read access to %s", sm.Name, repoID)
		}
		if _, ok := cfg.Credentials[grant.Credential]; !ok {
			return nil, fmt.Errorf("submodule %q: credential %q is not configured", sm.Name, grant.Credential)
		}
		if !seen[grant.Credential] {
			seen[grant.Credential] = true
			credsNeeded = append(credsNeeded, grant.Credential)
		}
	}
	return credsNeeded, nil
}

// githubRepoFromURL extracts "org/name" from an SSH or HTTPS GitHub URL.
func githubRepoFromURL(url, host string) (string, bool) {
	url = strings.TrimSuffix(strings.TrimSpace(url), ".git")
	lower := strings.ToLower(url)
	h := strings.ToLower(host)
	var rest string
	if i := strings.Index(lower, h+":"); i >= 0 { // ssh: git@github.com:org/name
		rest = url[i+len(h)+1:]
	} else if i := strings.Index(lower, h+"/"); i >= 0 { // https://github.com/org/name
		rest = url[i+len(h)+1:]
	} else {
		return "", false
	}
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[0] + "/" + parts[1], true
}
