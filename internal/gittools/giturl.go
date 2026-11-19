package gittools

import "strings"

// ParseGitURL extracts the host and repository path ("org/name") from a git
// remote URL in scp-like (git@github.com:org/name), ssh:// or https:// form.
// The authority is parsed precisely instead of substring-matched, so
// look-alike hosts such as "evil-github.com" never match "github.com".
func ParseGitURL(raw string) (host, repoPath string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		return parseAuthorityForm(s[i+3:])
	}
	return parseScpForm(s)
}

// parseAuthorityForm handles scheme://[user@]host[:port]/path
func parseAuthorityForm(s string) (string, string, bool) {
	i := strings.Index(s, "/")
	if i <= 0 {
		return "", "", false
	}
	authority, path := s[:i], s[i+1:]
	if j := strings.LastIndex(authority, "@"); j >= 0 {
		authority = authority[j+1:]
	}
	if j := strings.LastIndex(authority, ":"); j >= 0 {
		authority = authority[:j]
	}
	if authority == "" || path == "" {
		return "", "", false
	}
	return authority, trimGitSuffix(path), true
}

// parseScpForm handles [user@]host:path (the OpenSSH scp-like syntax). Paths
// that begin with "/" or ":" are rejected so absolute paths and ext-protocol
// URLs ("ext::command") can never be misread as a repository path.
func parseScpForm(s string) (string, string, bool) {
	rest := s
	if at := strings.Index(s, "@"); at >= 0 {
		rest = s[at+1:]
	}
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return "", "", false
	}
	host, path := rest[:colon], rest[colon+1:]
	if host == "" || path == "" || strings.Contains(host, "/") ||
		strings.HasPrefix(path, "/") || strings.HasPrefix(path, ":") {
		return "", "", false
	}
	return host, trimGitSuffix(path), true
}

func trimGitSuffix(p string) string {
	return strings.TrimSuffix(p, ".git")
}
