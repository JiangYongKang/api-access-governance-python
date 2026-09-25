# API Access Governance

基于 FastAPI 的本地 HTTP 服务，提供多租户访问控制与配额治理能力。所有状态
（凭证、配额用量、审计流水）持久化在本地 SQLite（默认 `governance.db`），
重启后判定结论保持一致。

## 授权模型

- **凭证**：`POST /credentials` 签发，绑定 `tenant_id` 与权限范围（scopes）。
  Token 格式为 `v1.<key_id>.<sig>`，`sig = HMAC-SHA256(secret, key_id)[:32]`；
  无法解析、key_id 未知或签名不匹配的 token 一律视为不可信并拒绝。
- **判定顺序**（短路）：凭证解析 → 权限范围检查 → 配额原子扣减 → 审计留痕。
- **受保护资源**：`GET /data` 需要 `Authorization: Bearer <token>` 且凭证
  含 `read` scope。判定发生在请求入口；已放行的在途请求不受后续轮换/撤销影响。

## 错误分类（可区分的判定原因）

| reason | 含义 | HTTP |
|---|---|---|
| `malformed_credential` | token 格式不可信 | 403 |
| `unknown_credential` | key_id 未知或签名不匹配 | 403 |
| `credential_revoked` | 凭证已撤销 | 403 |
| `credential_expired` | 凭证已过期或兼容窗口已结束 | 403 |
| `insufficient_scope` | 缺少 endpoint 所需 scope | 403 |
| `quota_exceeded` | 超出租户×接口配额 | 429 |
| `audit_failure` | 审计写入失败，请求被拒绝（绝不静默放行） | 403 |

每次拒绝的响应体包含 `request_id`、`reason` 与 `detail`，并写入审计流水。

## 轮换与兼容窗口

- `POST /credentials/{key_id}/rotate`：签发同租户、同 scopes 的新凭证；
  旧凭证进入兼容窗口（默认 30 秒，`CredentialManager(grace_seconds=...)` 可调）。
  窗口内旧 token 仍被接受——保证轮换前已发出的在途请求语义确定；
  窗口结束后旧 token 按 `credential_expired` 拒绝。
- `POST /credentials/{key_id}/revoke`：撤销立即生效并终止兼容窗口，
  此后旧 token 一律按 `credential_revoked` 拒绝。

## 配额语义

- 维度：`(tenant_id, endpoint)`，通过 `PUT /quota/limits` 配置上限；
  未配置上限的维度默认放行且不计数。
- **原子扣减**：`try_consume_quota` 在单锁单事务内完成“检查 + 计数”，
  并发请求不会突破上限。
- **无幽灵配额**：只有实际放行的请求才计数；凭证/权限类拒绝发生在扣减
  之前，不占用配额。
- **持久化**：用量存于 SQLite，重启后已用量保留，超限判定结论一致。

## 审计流水

- 事件：`access_denied`（含判定依据与请求标识）、`credential_issued`、
  `credential_rotated`、`credential_revoked`。
- 写入在事务内提交，并发下不丢失、不重复（`seq` 自增唯一）。
- 审计写入失败时，授权结论为 `audit_failure` 拒绝，不会静默放行。
- 查询：`GET /audit?tenant_id=...&event=...`。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q        # 运行测试（并发配额竞争、轮换/撤销在途请求、
                        # 权限不足、过期、审计并发与故障注入）
uv run uvicorn main:app # 启动服务
```

手工验证示例：

```bash
TOKEN=$(curl -s -X POST localhost:8000/credentials \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"t1","scopes":["read"],"ttl_seconds":3600}' | jq -r .token)
curl -s localhost:8000/data -H "Authorization: Bearer $TOKEN"
curl -s "localhost:8000/audit?tenant_id=t1"
```

测试日志会打印每条请求的 `request_id`、命中的规则（`reason`）与判定依据
（`detail`），可用 `uv run pytest -s` 查看。
