// Package session owns the lifecycle of per-session git execution containers.
//
// Containers are created lazily per (MCP session, repository) pair, mount only
// that repository's workspace subdirectory plus the session ssh-agent socket,
// and carry no credentials of any kind.
package session

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/local/git-mcp-gateway/internal/config"
)

// Managed labels applied to every container the gateway creates.
const (
	LabelManaged = "git-mcp.managed"
	LabelSession = "git-mcp.session"
	LabelRepo    = "git-mcp.repo"
	LabelUser    = "git-mcp.user"
)

// Active describes one live session container.
type Active struct {
	SessionID string
	Repo      string
	User      string
	Container string
	LastUsed  time.Time
}

// Manager talks to the Docker daemon and tracks live session containers.
type Manager struct {
	cli   *client.Client
	store *config.Store

	mu   sync.Mutex
	live map[string]*Active // key: sessionID+"|"+repoID
}

// New connects to the local Docker daemon.
func New(store *config.Store) (*Manager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Manager{cli: cli, store: store, live: map[string]*Active{}}, nil
}

// key builds the live-map key.
func key(sessionID, repoID string) string { return sessionID + "|" + repoID }

// EnsureContainer returns a running container for (session, repo), creating it
// when needed. hostRepoPath is the absolute host path of the workspace
// subdirectory; agentSocket the session ssh-agent socket on the host.
func (m *Manager) EnsureContainer(ctx context.Context, sessionID, repoID, user, hostRepoPath, agentSocket string) (string, error) {
	cfg := m.store.Get()
	m.mu.Lock()
	if a, ok := m.live[key(sessionID, repoID)]; ok {
		a.LastUsed = time.Now()
		id := a.Container
		m.mu.Unlock()
		// make sure it is still running
		if _, err := m.cli.ContainerInspect(ctx, id); err != nil {
			m.forget(sessionID, repoID)
			return m.create(ctx, sessionID, repoID, user, hostRepoPath, agentSocket, cfg)
		}
		return id, nil
	}
	m.mu.Unlock()
	return m.create(ctx, sessionID, repoID, user, hostRepoPath, agentSocket, cfg)
}

func (m *Manager) create(ctx context.Context, sessionID, repoID, user, hostRepoPath, agentSocket string, cfg *config.Config) (string, error) {
	u := cfg.Users[user]
	cc := &container.Config{
		Image: cfg.Server.SessionImage,
		Env: []string{
			"SSH_AUTH_SOCK=" + "/ssh-agent/agent.sock",
			"GIT_AUTHOR_NAME=" + u.Name,
			"GIT_AUTHOR_EMAIL=" + u.Email,
			"GIT_COMMITTER_NAME=" + u.Name,
			"GIT_COMMITTER_EMAIL=" + u.Email,
		},
		WorkingDir: "/workspace",
		User:       "1000:1000",
		Labels: map[string]string{
			LabelManaged: "1",
			LabelSession: sessionID,
			LabelRepo:    repoID,
			LabelUser:    user,
		},
	}
	hc := &container.HostConfig{
		Binds: []string{
			hostRepoPath + ":/workspace:rw",
			agentSocket + ":" + "/ssh-agent/agent.sock:rw",
		},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges"},
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024,
			NanoCPUs:  1e9,
			PidsLimit: int64Ptr(128),
		},
	}
	created, err := m.cli.ContainerCreate(ctx, cc, hc, nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("create session container (is image %q built/pulled?): %w", cfg.Server.SessionImage, err)
	}
	if err := m.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		_ = m.cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("start session container: %w", err)
	}
	m.mu.Lock()
	m.live[key(sessionID, repoID)] = &Active{
		SessionID: sessionID, Repo: repoID, User: user,
		Container: created.ID, LastUsed: time.Now(),
	}
	m.mu.Unlock()
	return created.ID, nil
}

// Exec runs a command inside the session container and returns the combined
// (raw) output, truncated to maxOut bytes.
func (m *Manager) Exec(ctx context.Context, containerID string, cmd []string, timeout time.Duration, maxOut int) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	exec, err := m.cli.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          cmd,
		WorkingDir:   "/workspace",
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", -1, fmt.Errorf("exec create: %w", err)
	}
	attach, err := m.cli.ContainerExecAttach(ctx, exec.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", -1, fmt.Errorf("exec attach: %w", err)
	}
	defer attach.Close()
	raw, _ := io.ReadAll(io.LimitReader(attach.Reader, int64(maxOut)+1))
	if len(raw) > maxOut {
		raw = raw[:maxOut]
	}
	inspect, err := m.cli.ContainerExecInspect(ctx, exec.ID)
	if err != nil {
		return string(raw), -1, fmt.Errorf("exec inspect: %w", err)
	}
	return string(raw), inspect.ExitCode, nil
}

// Destroy stops and removes the container for (session, repo).
func (m *Manager) Destroy(ctx context.Context, sessionID, repoID string) {
	m.mu.Lock()
	a, ok := m.live[key(sessionID, repoID)]
	if ok {
		delete(m.live, key(sessionID, repoID))
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	timeout := 5
	_ = m.cli.ContainerStop(ctx, a.Container, container.StopOptions{Timeout: &timeout})
	_ = m.cli.ContainerRemove(ctx, a.Container, container.RemoveOptions{Force: true})
}

// Forget drops the tracking entry without touching the container (used when
// inspecting reveals an externally-removed container).
func (m *Manager) forget(sessionID, repoID string) {
	m.mu.Lock()
	delete(m.live, key(sessionID, repoID))
	m.mu.Unlock()
}

// ActiveSessions lists live session containers.
func (m *Manager) ActiveSessions() []Active {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Active, 0, len(m.live))
	for _, a := range m.live {
		out = append(out, *a)
	}
	return out
}

// Get returns tracking info for one (session, repo) pair.
func (m *Manager) Get(sessionID, repoID string) (Active, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.live[key(sessionID, repoID)]
	return *a, ok
}

// KillOrphans terminates managed containers left behind by a previous
// gateway process. Persistent workspaces keep their state, so an interrupted
// git session loses nothing but the in-flight command.
func (m *Manager) KillOrphans(ctx context.Context) (int, error) {
	list, err := m.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("label", LabelManaged+"=1")),
	})
	if err != nil {
		return 0, err
	}
	killed := 0
	for _, c := range list {
		timeout := 2
		_ = m.cli.ContainerStop(ctx, c.ID, container.StopOptions{Timeout: &timeout})
		_ = m.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true})
		killed++
	}
	return killed, nil
}

// IsNotFound reports whether the error means "no such container/exec".
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return client.IsErrNotFound(err) || strings.Contains(err.Error(), "No such container") ||
		strings.Contains(err.Error(), "no such exec")
}

func int64Ptr(v int64) *int64 { return &v }

// Close closes the docker client.
func (m *Manager) Close() error { return m.cli.Close() }

var _ = types.IDResponse{} // keep import stable across SDK versions
