package mcpapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/creds"
	"github.com/local/git-mcp-gateway/internal/gittools"
	"github.com/local/git-mcp-gateway/internal/repo"
	"github.com/local/git-mcp-gateway/internal/sanitize"
)

func sanitizeText(s string) string { return sanitize.Clean(s) }

// toolDef describes one MCP tool. Run performs the full orchestration.
type toolDef struct {
	Name        string
	Description string
	Schema      map[string]any
	Run         func(ctx context.Context, c *callCtx, args map[string]any) (string, error)
}

// repoTool wraps a repository-scoped git tool: it extracts the repo argument
// and delegates to the orchestration core with the required action.
func repoTool(name, desc, action string, schema map[string]any,
	build func(c *callCtx, a map[string]any, cloned bool) ([]string, error)) toolDef {
	return toolDef{
		Name: name, Description: desc, Schema: schema,
		Run: func(ctx context.Context, c *callCtx, a map[string]any) (string, error) {
			repoID, err := strArg(a, "repo")
			if err != nil {
				return "", err
			}
			return c.runGit(ctx, repoID, action, func(cloned bool) ([]string, error) {
				return build(c, a, cloned)
			})
		},
	}
}

func strArg(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("argument %q must be a non-empty string", key)
	}
	return s, nil
}

func optString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func optBool(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

func optInt(args map[string]any, key string) int {
	if f, ok := args[key].(float64); ok {
		return int(f)
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func arrProp(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func repoProp() map[string]any {
	return strProp("repository identifier, e.g. org/name (must be registered and granted)")
}

// runGit is the orchestration core: authorize → lock → verify workspace →
// aggregate agent keys → ensure container → (clone if needed) → exec.
func (c *callCtx) runGit(ctx context.Context, repoID, action string, build func(cloned bool) ([]string, error)) (string, error) {
	s := c.s
	cfg := s.Store.Get()
	if _, ok := cfg.Repos[repoID]; !ok {
		return "", fmt.Errorf("unknown repo %q", repoID)
	}
	grant, ok := cfg.GrantFor(c.user(), repoID)
	if !ok {
		s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "authz",
			Repo: repoID, Result: "denied", Detail: "no grant"})
		return "", fmt.Errorf("permission denied: no grant on %s", repoID)
	}
	if !grant.HasAction(action) {
		s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "authz",
			Repo: repoID, Tool: action, Result: "denied", Detail: "action not granted"})
		return "", fmt.Errorf("permission denied: %s not granted on %s", action, repoID)
	}

	_, path, err := s.Repos.Resolve(repoID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", fmt.Errorf("workspace directory: %w", err)
	}

	cloned := true
	if err := s.Repos.Precheck(repoID); err != nil {
		if err == repo.ErrNotCloned {
			cloned = false
		} else {
			s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "tool",
				Repo: repoID, Result: "error", Detail: err.Error()})
			return "", err
		}
	}

	credNames := []string{grant.Credential}
	if cloned {
		extra, err := s.resolveSubmodules(c.user(), path)
		if err != nil {
			s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "tool",
				Repo: repoID, Result: "denied", Detail: err.Error()})
			return "", err
		}
		credNames = append(credNames, extra...)
	}

	privateKeys, err := s.loadPrivateKeys(credNames)
	if err != nil {
		return "", err
	}
	ag, err := s.Pool.StartSession(c.sid(), privateKeys)
	if err != nil {
		return "", err
	}
	// If the agent already existed, make sure keys that became necessary only
	// now (e.g. submodule repositories) are added to it as well.
	if _, ok := s.Pool.Get(c.sid()); ok {
		for _, k := range privateKeys {
			_ = ag.AddKey(k)
		}
	}

	containerID, err := s.Sess.EnsureContainer(ctx, c.sid(), repoID, c.user(), path, ag.Socket)
	if err != nil {
		return "", err
	}

	if !cloned {
		url := fmt.Sprintf("git@%s:%s.git", cfg.Server.GitHubHost, repoID)
		out, code, execErr := s.Sess.Exec(ctx, containerID, []string{"git", "clone", url, "/workspace"},
			cfg.Server.ExecTimeout, cfg.Server.MaxOutputBytes)
		if execErr != nil {
			return "", execErr
		}
		if code != 0 {
			return "", fmt.Errorf("git clone failed (exit %d): %s", code, sanitizeText(out))
		}
		s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "tool",
			Repo: repoID, Session: c.sid(), Credential: grant.Credential, Result: "ok",
			Detail: "workspace cloned"})
	}

	cmd, err := build(cloned)
	if err != nil {
		return "", err
	}
	out, code, execErr := s.Sess.Exec(ctx, containerID, cmd, cfg.Server.ExecTimeout, cfg.Server.MaxOutputBytes)
	s.Repos.Touch(repoID)
	if execErr != nil {
		return "", execErr
	}
	s.Audit.Log(audit.Event{Actor: c.user(), ActorType: "user", Event: "tool",
		Repo: repoID, Tool: cmd[1], Session: c.sid(), Credential: grant.Credential,
		Result: map[bool]string{true: "ok", false: "error"}[code == 0],
		Detail: fmt.Sprintf("exit=%d", code)})
	if code != 0 {
		return "", fmt.Errorf("git %s failed (exit %d): %s", cmd[1], code, sanitizeText(out))
	}
	return sanitizeText(out), nil
}

// loadPrivateKeys decrypts the listed credentials and parses them into crypto
// private keys. Plaintext key bytes are zeroed immediately after parsing;
// only the parsed key objects stay in memory.
func (s *Server) loadPrivateKeys(credNames []string) ([]any, error) {
	key, err := creds.GlobalMasterKey()
	if err != nil {
		return nil, err
	}
	cfg := s.Store.Get()
	var out []any
	seen := map[string]bool{}
	for _, name := range credNames {
		if seen[name] {
			continue
		}
		seen[name] = true
		cred, ok := cfg.Credentials[name]
		if !ok {
			return nil, fmt.Errorf("credential %q is not configured", name)
		}
		plain, err := creds.LoadPlaintext(key, cred.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("credential %q: %w", name, err)
		}
		raw, perr := creds.ParseRawPrivateKey(plain)
		creds.Zero(plain)
		if perr != nil {
			return nil, fmt.Errorf("credential %q: %w", name, perr)
		}
		out = append(out, raw)
	}
	return out, nil
}

// toolDefs returns the MCP tool catalogue.
func (s *Server) toolDefs() []map[string]any {
	out := []map[string]any{}
	for _, d := range s.tools {
		out = append(out, map[string]any{
			"name":        d.Name,
			"description": d.Description,
			"inputSchema": d.Schema,
		})
	}
	return out
}

func (s *Server) toolByName(name string) (toolDef, bool) {
	for _, d := range s.tools {
		if d.Name == name {
			return d, true
		}
	}
	return toolDef{}, false
}

func (s *Server) initTools() {
	s.tools = []toolDef{
		repoTool("git_status",
			"Show working tree status (porcelain + branch info) of a registered repository.",
			config.ActionRead,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "status", "--porcelain=v1", "-b"}, nil
			}),

		repoTool("git_diff",
			"Show unstaged diff (staged=true for staged changes).",
			config.ActionRead,
			objSchema(map[string]any{"repo": repoProp(), "staged": boolProp("show staged changes instead")}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				if optBool(a, "staged") {
					return []string{"git", "diff", "--staged"}, nil
				}
				return []string{"git", "diff"}, nil
			}),

		repoTool("git_log",
			"Show recent commit history (oneline, newest first).",
			config.ActionRead,
			objSchema(map[string]any{"repo": repoProp(), "limit": intProp("max entries (default 20, cap 100)")}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "log", "--oneline", "-n", gittools.LogLimit(optInt(a, "limit"))}, nil
			}),

		repoTool("git_branch_list",
			"List local and remote branches with tip commits.",
			config.ActionRead,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "branch", "-a", "-v"}, nil
			}),

		repoTool("git_create_branch",
			"Create a new branch (optionally from a start point).",
			config.ActionClone,
			objSchema(map[string]any{
				"repo": repoProp(), "name": strProp("new branch name"), "from": strProp("optional start point"),
			}, "repo", "name"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				name, err := strArg(a, "name")
				if err != nil {
					return nil, err
				}
				if err := gittools.ValidateRefName(name); err != nil {
					return nil, err
				}
				if from := optString(a, "from"); from != "" {
					if err := gittools.ValidateRefName(from); err != nil {
						return nil, err
					}
					return []string{"git", "branch", name, from}, nil
				}
				return []string{"git", "branch", name}, nil
			}),

		repoTool("git_checkout",
			"Check out a branch or tag.",
			config.ActionClone,
			objSchema(map[string]any{
				"repo": repoProp(), "branch": strProp("branch or tag to check out"),
			}, "repo", "branch"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				branch, err := strArg(a, "branch")
				if err != nil {
					return nil, err
				}
				if err := gittools.ValidateRefName(branch); err != nil {
					return nil, err
				}
				return []string{"git", "checkout", branch}, nil
			}),

		repoTool("git_clone",
			"Clone the registered repository into its persistent workspace; if already cloned, fetch all remotes instead.",
			config.ActionClone,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				if cloned {
					return []string{"git", "fetch", "--all", "--prune"}, nil
				}
				repoID, err := strArg(a, "repo")
				if err != nil {
					return nil, err
				}
				host := c.s.Store.Get().Server.GitHubHost
				return []string{"git", "clone", fmt.Sprintf("git@%s:%s.git", host, repoID), "/workspace"}, nil
			}),

		repoTool("git_fetch",
			"Fetch all remotes with pruning.",
			config.ActionClone,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "fetch", "--all", "--prune"}, nil
			}),

		repoTool("git_pull",
			"Fast-forward pull from the tracking remote.",
			config.ActionClone,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "pull", "--ff-only"}, nil
			}),

		repoTool("git_add",
			"Stage changes. Without paths, everything (-A) is staged.",
			config.ActionPush,
			objSchema(map[string]any{
				"repo": repoProp(), "paths": arrProp("relative paths to stage"),
			}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				raw, _ := a["paths"].([]any)
				if len(raw) == 0 {
					return []string{"git", "add", "-A"}, nil
				}
				cmd := []string{"git", "add", "--"}
				for _, p := range raw {
					ps, _ := p.(string)
					if err := gittools.ValidateRelPath(ps); err != nil {
						return nil, err
					}
					cmd = append(cmd, ps)
				}
				return cmd, nil
			}),

		repoTool("git_commit",
			"Commit staged changes with a message (author identity is injected by the gateway).",
			config.ActionPush,
			objSchema(map[string]any{
				"repo": repoProp(), "message": strProp("commit message"),
			}, "repo", "message"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				msg, err := strArg(a, "message")
				if err != nil {
					return nil, err
				}
				return []string{"git", "commit", "-m", msg}, nil
			}),

		repoTool("git_push",
			"Push a local branch to origin (main pushes are allowed if granted).",
			config.ActionPush,
			objSchema(map[string]any{
				"repo": repoProp(), "branch": strProp("local branch to push"),
			}, "repo", "branch"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				branch, err := strArg(a, "branch")
				if err != nil {
					return nil, err
				}
				if err := gittools.ValidateRefName(branch); err != nil {
					return nil, err
				}
				return []string{"git", "push", "origin", branch}, nil
			}),

		repoTool("git_stash_push",
			"Stash current changes (optional message).",
			config.ActionPush,
			objSchema(map[string]any{
				"repo": repoProp(), "message": strProp("optional stash message"),
			}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				if msg := optString(a, "message"); msg != "" {
					return []string{"git", "stash", "push", "-m", msg}, nil
				}
				return []string{"git", "stash", "push"}, nil
			}),

		repoTool("git_stash_pop",
			"Pop the latest stash.",
			config.ActionPush,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				return []string{"git", "stash", "pop"}, nil
			}),

		repoTool("git_submodule_update",
			"Initialize/update git submodules (single level; every submodule repo must be registered and granted; .gitmodules is validated first).",
			config.ActionClone,
			objSchema(map[string]any{"repo": repoProp()}, "repo"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				if !cloned {
					return nil, fmt.Errorf("workspace not cloned yet; run git_clone first")
				}
				return []string{"git", "submodule", "update", "--init"}, nil
			}),

		repoTool("run_git",
			"Run an allowlisted git command (e.g. [\"git\",\"log\",\"--oneline\",\"-n\",\"5\"]). Dangerous flags and subcommands are rejected.",
			config.ActionRead,
			objSchema(map[string]any{
				"repo": repoProp(), "args": arrProp("full git command line, starting with \"git\""),
			}, "repo", "args"),
			func(c *callCtx, a map[string]any, cloned bool) ([]string, error) {
				raw, _ := a["args"].([]any)
				args := make([]string, 0, len(raw))
				for _, v := range raw {
					sv, _ := v.(string)
					args = append(args, sv)
				}
				if err := gittools.CheckRunArgs(args); err != nil {
					return nil, err
				}
				return args, nil
			}),
	}
}

// pathInside is a helper for future path-sensitive tools.
func pathInside(root, p string) (string, error) {
	joined := filepath.Join(root, p)
	if !strings.HasPrefix(joined, filepath.Clean(root)+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository")
	}
	return joined, nil
}

var _ = ssh.FingerprintSHA256
