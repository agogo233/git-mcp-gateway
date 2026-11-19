// git-mcp-gateway is a team-shared MCP server that performs git operations
// inside disposable containers while keeping SSH deploy keys inside the
// gateway process. See README.md for the architecture and deployment guide.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/local/git-mcp-gateway/internal/admin"
	"github.com/local/git-mcp-gateway/internal/audit"
	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/config"
	"github.com/local/git-mcp-gateway/internal/creds"
	"github.com/local/git-mcp-gateway/internal/mcpapi"
	"github.com/local/git-mcp-gateway/internal/repo"
	"github.com/local/git-mcp-gateway/internal/session"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keytool" {
		runKeytool(os.Args[2:])
		return
	}
	dir := flag.String("config", "/etc/git-mcp-gateway", "configuration directory (users.yaml, grants.yaml, repos.yaml, server.yaml)")
	addr := flag.String("addr", "", "override listen address")
	flag.Parse()

	fmt.Printf("git-mcp-gateway %s starting (config: %s)\n", version, *dir)

	// 1. Configuration (fail fast on invalid files).
	cfg, err := config.Load(*dir)
	if err != nil {
		fatal("configuration: %v", err)
	}

	// 2. Master key must be present and valid before anything else happens.
	if _, err := creds.GlobalMasterKey(); err != nil {
		fatal("master key: %v", err)
	}

	// 3. Audit log.
	auditLog, err := audit.Open(cfg.Server.AuditFile)
	if err != nil {
		fatal("audit log: %v", err)
	}
	defer auditLog.Close()

	// 4. Hot-reloading config store.
	store, err := config.NewStore(*dir, func(c *config.Config) {
		if c == nil {
			auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "config",
				Result: "error", Detail: "configuration reload failed; keeping previous configuration"})
			return
		}
		auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "config",
			Result: "ok", Detail: "configuration reloaded"})
	})
	if err != nil {
		fatal("config store: %v", err)
	}
	cfg = store.Get()

	// 5. Startup self-healing: wipe stale agent sockets, kill orphan session
	// containers left by a previous process. Persistent workspaces keep their
	// state, so nothing but an in-flight command is lost.
	pool, err := creds.NewAgentPool(cfg.Server.SocketDir)
	if err != nil {
		fatal("agent pool: %v", err)
	}
	sessMgr, err := session.New(store)
	if err != nil {
		fatal("docker session manager: %v", err)
	}
	// Report an unreachable Docker daemon at startup, but do not abort: the
	// gateway can still serve /healthz and the admin console, and the CI
	// smoke test intentionally starts the image without a docker socket.
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := sessMgr.Ping(pingCtx); err != nil {
		auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "session",
			Result: "error", Detail: "docker daemon unreachable at startup: " + err.Error()})
	}
	cancelPing()
	orphans, err := sessMgr.KillOrphans(context.Background())
	if err != nil {
		auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "session",
			Result: "error", Detail: "orphan scan failed: " + err.Error()})
	} else if orphans > 0 {
		auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "session",
			Result: "ok", Detail: fmt.Sprintf("killed %d orphan session container(s) at startup", orphans)})
	}
	repoMgr := repo.New(store)

	// 6. HTTP surface: /mcp for agents, /admin for the console, /healthz liveness.
	authn := auth.New(store)
	mcpSrv := mcpapi.New(store, authn, auditLog, repoMgr, sessMgr, pool, version)
	adminSrv := &admin.Server{
		Store: store, Auth: authn, Audit: auditLog, Repos: repoMgr,
		Sess: sessMgr, Pool: pool, Version: version,
	}

	mux := http.NewServeMux()
	mcpSrv.Register(mux)
	adminSrv.Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": version})
	})

	// 7. Idle-session reaper.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mcpSrv.StartReaper(ctx)

	listenAddr := cfg.Server.Addr
	if *addr != "" {
		listenAddr = *addr
	}
	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "session",
		Result: "ok", Detail: "gateway listening on " + listenAddr})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Printf("listening on %s\n", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("http server: %v", err)
	}
	auditLog.Log(audit.Event{Actor: "system", ActorType: "system", Event: "session",
		Result: "ok", Detail: "gateway stopped"})
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}
