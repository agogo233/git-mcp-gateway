# git-mcp-gateway

团队共享的 git MCP 服务：Agent（LLM）通过 MCP 工具执行 **git 全功能操作**，而 **SSH 私钥永不离开网关进程**。

```
开发者浏览器 ──► OpenCodeUI frontend(:3000)
                     │
               opencode backend 容器（/workspace = 宿主机 workspace，多仓库子目录）
                     │  MCP: http://git-mcp-gateway:8443/mcp
                     ▼
              opencode-net（docker 网络，内网明文）
                     ▼
        git-mcp-gateway（本仓库，独立 compose）
          ├─ /mcp   Agent 工具面（Bearer token 认证）
          ├─ /admin Web 管理台（admin token，同端口）
          ├─ 授权表：user × repo → actions → deploy key
          ├─ 审计日志 + 输出脱敏 + run_git 白名单
          ├─ 私钥：磁盘只存加密 blob，运行时解密进内存 ssh-agent
          └─ 会话容器编排（Docker SDK）
                     ▼
        session 容器（alpine+git+openssh，无任何密钥）
          只挂载 <workspace>/<repo> + agent socket
                     │ git push（签名经 socket 回网关内存 agent）
                     ▼
                GitHub（deploy key 验签）
```

## 核心安全模型

1. **密钥零暴露**：deploy key 私钥以 NaCl secretbox 加密落盘（主密钥在 `GIT_MCP_MASTER_KEY` 环境变量），运行时解密进网关进程内存中的 `ssh-agent`，通过 UNIX socket 注入会话容器。容器与 LLM 上下文中永远没有私钥。
2. **授权表**：`user × repo → actions(read/clone/push) → credential`，配置热更新；越权调用直接拒绝并审计。`run_git` 按子命令二次鉴权（`add/commit/push/merge/rebase/...` 需 push、`pull/fetch/checkout/...` 需 clone），只读授权永远无法借道 `run_git` 执行写操作。
3. **会话绑定身份**：MCP 会话（`Mcp-Session-Id`）与认证用户绑定，持有他人 sid 的合法 token 也会被 403 拒绝并审计。
4. **最小暴露容器**：session 容器只挂载目标仓库子目录与 agent socket，无 docker.sock、无密钥文件、cap drop ALL、no-new-privileges、资源限额。
5. **高危拦截**：`push --force`、`push --force-with-lease`（含 `=ref:expect` 变体）、`reset --hard`、`commit --amend`、删除型 refspec、`git config`、`git remote set-url`、submodule 任意命令等一律拒绝；submodule 走受控工具并校验 `.gitmodules`（仅 GitHub URL、仅单层、逐仓授权）。
6. **输出脱敏**：所有返回给 Agent 的内容经过 token/私钥/JWT/URL 凭据正则清洗。
7. **全量审计**：认证、授权拒绝、会话生命周期、每次 git 执行（含完整命令行）、管理台操作均落 JSONL 审计日志。
8. **内存加固**：私钥明文即用即弃、用后置零；部署要求禁用 swap、关闭 core dump。
9. **持久工作区 + 仓库互斥锁**：仓库目录长期保留，同一仓库同一时刻只允许一个会话容器操作（工具编排全程持锁，管理台可强制解锁）。

## 目录结构

```
main.go                     入口（含 keytool 子命令）
internal/config             配置加载/校验/热更新（users/grants/repos/server）
internal/auth               Bearer token 认证（bcrypt）
internal/authz              （并入 config.GrantFor/HasAction）
internal/audit              JSONL 审计日志
internal/sanitize           输出脱敏
internal/creds              私钥加密存取 + 会话内存 agent 池
internal/repo               持久工作区管理、remote 校验、互斥锁
internal/session            会话容器编排（Docker SDK）
internal/gittools           run_git 白名单与参数校验
internal/mcpapi             MCP Streamable HTTP + 工具编排
internal/admin              Web 管理台（go:embed 静态页）
docker/Dockerfile.gateway   网关镜像（多阶段，非 root）
docker/Dockerfile.session   会话镜像（git+ssh，构建时 pin GitHub host key）
deploy/docker-compose.yml   独立部署（external 接入 opencode-net）
.github/workflows/          CI（测试+镜像 smoke）与 Docker 发布（GHCR）
config/*.example.yaml       配置样例（真实配置不进 git）
```

## 首次部署

### 0. 前提

- 服务器已安装 Docker + Compose；OpenCodeUI 已按 `docker-compose.simple.yml` 启动（创建了 `opencode-net` 网络）
- 宿主机目录：`/var/lib/git-mcp/keys`、`/run/git-mcp`、`/var/log/git-mcp`、持久工作区根目录（如 `/srv/workspaces`），均属主为 uid 1000（`chown -R 1000:1000 ...`）
- 宿主机 swap 已禁用（`swapoff -a` 并注释 fstab），core dump 已关闭

### 1. 生成主密钥与配置

```bash
cp .env.example .env && chmod 600 .env
echo "GIT_MCP_MASTER_KEY=$(openssl rand -base64 32)" >> .env   # 主密钥务必离线另存一份
# 编辑 .env 其余项；复制 config/*.example.yaml 为 config/*.yaml 并按注释填写
```

### 2. 构建并启动

```bash
docker compose -f deploy/docker-compose.yml up -d --build
curl http://127.0.0.1:8443/healthz
```

### 3. 生成用户 token 与 deploy key

打开管理台 `http://<服务器>:8443/admin/`，用 admin token 登录（首个 admin token 哈希写进 `config/users.yaml` 的 `admin_token_hash`，明文只留给自己）：

- 「用户」页创建 alice/bob，**token 明文只显示一次**
- 「凭据」页为每个仓库生成 deploy key —— 页面返回**公钥**（一次性显示），私钥已自动加密入库
- 把公钥登记到对应 GitHub 仓库的 Settings → Deploy keys（需要 push 的勾选 Allow write access）
- 「授权」页核对/保存授权表

也可以纯 CLI：

```bash
docker exec git-mcp-gateway git-mcp-gateway keytool hash -t <token>
docker exec git-mcp-gateway git-mcp-gateway keytool gen-deploy-key -name git-mcp:alice -pub /tmp/a.pub -o /keys/key-alice.age
```

### 4. OpenCodeUI 接入

在 opencode 的 MCP 配置中加入：

```json
{ "mcpServers": { "git": {
    "type": "http",
    "url": "http://git-mcp-gateway:8443/mcp",
    "headers": { "Authorization": "Bearer <该用户的token>" }
} } }
```

Agent 可用工具：`git_status / git_diff / git_log / git_branch_list / git_create_branch / git_checkout / git_clone / git_fetch / git_pull / git_add / git_commit / git_push / git_stash_push / git_stash_pop / git_submodule_update / run_git`。

## 验收清单

- [ ] alice 推送自己仓库 → 成功；bob 推送（只读凭据）→ 拒绝且有审计
- [ ] bob（read/clone 授权）用 `run_git` 传 `["git","push","origin","main"]` → `permission denied: push not granted`
- [ ] 用 bob 的 token 调 alice 的仓库 → `permission denied`；用 bob 的 token 复用 alice 的 `Mcp-Session-Id` → 403
- [ ] `run_git` 传 `push --force` / `push --force-with-lease=main:abc` / `reset --hard` / `remote set-url` → 被拒
- [ ] session 容器内 `find / -name "*.age" -o -name "id_*"` → 无私钥文件
- [ ] 审计日志可见每次操作归因到 用户×仓库×凭据×完整命令
- [ ] 同仓库并发第二个会话 → 被互斥锁拒绝
- [ ] gateway 端口默认只绑 `127.0.0.1`（容器间走 opencode-net 直连）

## 回滚

任何阶段 `docker compose -f deploy/docker-compose.yml down` + 移除 opencode 里的 MCP 配置即恢复原状；密钥随时可在 GitHub 侧删除 deploy key、服务器侧删除 `.age` 文件并在管理台移除凭据。镜像可用 GHCR 的 `sha-xxxxxxx` tag 精确回退。

## 已知边界（设计取舍，详见方案评审记录）

- gateway 容器持有 docker.sock（等同宿主机 root 权限），镜像最小化 + 只读配置缓解
- deploy key 不过期：靠会话 TTL、授权粒度与审计兜底；后续可切 Vault SSH CA 短时证书或 GitHub App 短时 token
- 内网明文传输：gateway 端口默认只绑宿主机 `127.0.0.1`，不对外网暴露；容器间走 opencode-net 直连，上 TLS 只需在反代层加
- Go GC 环境下内存加固非绝对（已做：即用即弃、置零、禁 swap、关 core dump；页锁为后续增强）
