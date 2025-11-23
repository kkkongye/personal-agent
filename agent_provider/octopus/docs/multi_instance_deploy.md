# 多实例部署指南（Windows / PowerShell）

本文档说明如何在同一台机器上运行多个 Octopus 实例，并为每个实例设置独立端口、日志文件、以及（可选）不同的 .env 配置。

## 目标
- 同时启动 A 与 B 两个实例
- 每个实例监听不同 HTTP 端口（例如 9527 与 9529）
- 每个实例写入各自的日志文件，避免竞争
- 可选择是否启用 ANP Receiver（同一个或不同网关）

## 关键参数
- 端口：`port`（或 CLI `--port`）
- ANP：`anp_sdk_enabled`（或 CLI `--anp/--no-anp`）；网关 `anp_gateway_ws_url`
- 日志：通过环境变量 `OCTOPUS_LOG_FILE` 指定日志路径（已在代码支持）
- OpenAI：`openai_base_url`、`openai_api_key`、`openai_model`

> 配置来源优先级：CLI 覆盖 > 环境变量 > `.env`

## 方案一：直接在 PowerShell 启动两个实例

在项目根目录执行以下命令，各自打开两个 PowerShell 窗口：

窗口 A：

```powershell
$env:OCTOPUS_LOG_FILE = "logs/octopus-A.log"
uv run python -m octopus.octopus --port 9527 --debug --log-level DEBUG
```

窗口 B：

```powershell
$env:OCTOPUS_LOG_FILE = "logs/octopus-B.log"
uv run python -m octopus.octopus --port 9529 --debug --log-level DEBUG
```

可选：如果你希望 A/B 使用不同的 ANP 网关或关闭 ANP：

```powershell
# 实例 A 使用网关，实例 B 关闭 ANP
# 窗口 A
$env:OCTOPUS_LOG_FILE = "logs/octopus-A.log"
uv run python -m octopus.octopus --port 9527 --anp-gateway wss://gateway.example/ws --anp --log-level INFO

# 窗口 B
$env:OCTOPUS_LOG_FILE = "logs/octopus-B.log"
uv run python -m octopus.octopus --port 9529 --no-anp --log-level INFO
```

## 方案二：使用不同的 .env 文件

你可以复制 `.env` 为 `.env.instance_a`、`.env.instance_b`，分别修改端口、OpenAI、ANP 等参数，再通过 `--config` 指定：

```powershell
# 窗口 A
$env:OCTOPUS_LOG_FILE = "logs/octopus-A.log"
uv run python -m octopus.octopus --config .env.instance_a --port 9527

# 窗口 B
$env:OCTOPUS_LOG_FILE = "logs/octopus-B.log"
uv run python -m octopus.octopus --config .env.instance_b --port 9529
```

> 注意：`--port` 会覆盖 `.env` 中的端口。若不想覆盖，可去掉 CLI 的 `--port`。

## 一键脚本（Windows PowerShell）

我们提供 `scripts/run-multi.ps1`，一键启动两个实例（见下节）。你也可以修改端口、日志路径或 .env 以适配你的环境。

## 健康检查与探活
- 应用健康：`/health` 返回 `{ "status": "healthy" }`
- ANP 状态：`/anp/status`
- Agent 列表：`/agents`
- AD 文件：`/ad.json`

可以对不同实例分别访问上述路径，例如：
- 实例 A: http://127.0.0.1:9527/health
- 实例 B: http://127.0.0.1:9529/health

## 负载均衡与反向代理（可选）
- 本地多实例通常配合 Nginx / IIS / Envoy / Traefik 做反向代理；将上游指向两个实例端口，实现轮询或自定义策略
- 若放到容器环境，建议使用 Docker Compose 或 Kubernetes 部署多个副本，映射不同容器端口，由 Service/Ingress 统一入口

## 常见问题
- 两个实例日志互相覆盖？
  - 通过 `OCTOPUS_LOG_FILE` 为每个实例指定不同日志路径
- 端口冲突？
  - 修改 `--port` 或 `.env` 中的 `port`
- 使用 0.0.0.0 导致客户端直连失败？
  - 客户端测试时请用 127.0.0.1 或实际 IP。我们在测试脚本中已做 0.0.0.0 -> 127.0.0.1 的兼容转换
- OpenAI 调用超时？
  - 优先使用官方 `https://api.openai.com/v1` 验证链路；或在 `octopus/master_agent.py` 中的超时、重试、fallback 已做增强

---

有需要把该文档扩展为容器化/CI 脚本的，请告诉我们你的目标环境（Docker/K8s/VM/裸机），我们可以继续补齐。