# API Access Governance

基于 FastAPI 的本地 HTTP 服务，提供多租户访问控制与配额治理能力。所有状态
（凭证、**配额策略**、总量用量、滚动窗口事件、判定追溯、审计流水）持久化在
本地 SQLite（默认 `governance.db`），重启后策略与判定结论保持一致，无需重新
手工下发。

## 授权模型

- **凭证**：`POST /credentials` 签发，绑定 `tenant_id` 与权限范围（scopes）。
  Token 格式为 `v1.<key_id>.<sig>`，`sig = HMAC-SHA256(secret, key_id)[:32]`；
  无法解析、key_id 未知或签名不匹配的 token 一律视为不可信并拒绝。
- **判定顺序**（短路）：凭证解析 → 权限范围检查 → **配额双层原子判定**
  （总量层 → 滚动窗口层）→ 追溯/审计留痕。
- **受保护资源**：`GET /data` 需要 `Authorization: Bearer <token>` 且凭证
  含 `read` scope。判定发生在请求入口；已放行的在途请求不受后续轮换/撤销影响。

## 配额策略（持久化、可动态调整）

策略以 `(tenant_id, endpoint)` 为 key 落盘，通过
`PUT /quota/policies` 下发或调整，**整条覆盖**：同一个 key 反复下发、往上调
或往下调，都以最后一次为准，被调掉的老策略（含旧窗口配置）不会残留。

请求体：

```json
{
  "tenant_id": "t1",
  "endpoint": "/data",
  "total_limit": 1000,
  "window_seconds": 60.0,
  "window_limit": 100
}
```

- `total_limit`：累计总量上限；`null` 表示总量层不限制。
- `window_seconds > 0` 且 `window_limit >= 1`：启用“每 `window_seconds` 秒
  最多 `window_limit` 次”的**滚动时间窗口**层；两者不配置表示窗口层不限制。
- 非法组合（如窗口次数 > 0 但窗口时长为 0）返回 422。

### 默认策略

`tenant_id` 取特殊值 `"*"` 表示**默认策略**，对所有没有专属策略的租户生效。
因此“没被单独配过的租户”不再是完全不限，而是受明确的默认上限约束。生效解析
顺序是确定的：

1. `(tenant_id, endpoint)` 专属策略存在 → **整条**生效（不与默认策略合并）；
2. 否则取 `("*", endpoint)` 默认策略；
3. 两者都没有 → 两层均不限制（`policy_source = none`）。

`GET /quota/{tenant_id}?endpoint=/data` 返回当前**真正生效**的两层上限、
已用量以及命中来源（`tenant` / `default` / `none`）；
`GET /quota/policies?endpoint=...` 列出已落盘策略。

### 总量层与窗口层叠加的语义

- 两层**同时生效**，任意一层到顶即拒绝：
  - 总量层到顶 → `reason=quota_exceeded`，HTTP 429，`limiting_layer=total`；
  - 窗口层到顶 → `reason=rate_limited`，HTTP 429，`limiting_layer=window`。
  判定先检查总量层再检查窗口层，响应体与追溯记录会明确报告被哪一层拦下。
- **滚动窗口**：窗口为半开区间 `(now - window_seconds, now]`；每次判定先原子
  清理滑出窗口的旧事件再计数，因此窗口自然滚动、到点自动重置。请求时间由
  判定入口传入，窗口边界（恰好等于 `now - window_seconds` 的事件被滑出）判定
  稳定、可解释。
- **原子记账，无幽灵配额**：“窗口滚动 → 两层检查 → 计数 → 判定追溯/审计
  落盘”在存储层的单把锁 + 单个 SQLite 事务内完成。并发下总量层与窗口层都
  不会被突破；被拒绝的请求不吃任何计数（总量与窗口都不吃）。
- **重启一致性**：策略、总量用量、窗口事件都在 SQLite 中。重启后窗口内已用量
  保留（仍可能拒绝），随时间自然滑过后恢复；总量已用量单调累计。

## 判定追溯（放行也可追溯）

每一笔判定——**无论放行还是拒绝**——都写入 `decision_trace`，可通过
`GET /decisions/{request_id}` 按请求标识查到：命中的规则（reason/layer）、
策略来源、当时两层的用量与上限、判定依据文本（detail）。审计流水中放行事件
为 `access_allowed`，拒绝为 `access_denied`，另有凭证生命周期事件。

### Fail-closed：链路异常绝不放行

策略读取、配额记账或追溯/审计落盘任一环节异常时，本次请求一律拒绝：

- 策略/记账链路异常 → `policy_failure`（HTTP 403）；
- 追溯/审计写入异常 → `audit_failure`（HTTP 403）。

不会因为治理链路故障而把请求悄悄放过去。

## 错误分类（可区分的判定原因）

| reason | 含义 | HTTP |
|---|---|---|
| `malformed_credential` | token 格式不可信 | 403 |
| `unknown_credential` | key_id 未知或签名不匹配 | 403 |
| `credential_revoked` | 凭证已撤销 | 403 |
| `credential_expired` | 凭证已过期或兼容窗口已结束 | 403 |
| `insufficient_scope` | 缺少 endpoint 所需 scope | 403 |
| `quota_exceeded` | 超出**总量层**上限（`limiting_layer=total`） | 429 |
| `rate_limited` | 超出**滚动窗口层**上限（`limiting_layer=window`） | 429 |
| `policy_failure` | 策略/记账链路异常，请求被拒绝（绝不静默放行） | 403 |
| `audit_failure` | 追溯/审计写入失败，请求被拒绝（绝不静默放行） | 403 |

每次拒绝的响应体包含 `request_id`、`reason`、`detail` 与 `limiting_layer`。

## 轮换与兼容窗口

- `POST /credentials/{key_id}/rotate`：签发同租户、同 scopes 的新凭证；
  旧凭证进入兼容窗口（默认 30 秒，`CredentialManager(grace_seconds=...)` 可调）。
  窗口内旧 token 仍被接受——保证轮换前已发出的在途请求语义确定；
  窗口结束后旧 token 按 `credential_expired` 拒绝。
- `POST /credentials/{key_id}/revoke`：撤销立即生效并终止兼容窗口，
  此后旧 token 一律按 `credential_revoked` 拒绝。

## 兼容范围

- 旧的“只配总量上限”用法完全保留：
  - `PUT /quota/limits` 风格的 `QuotaLimiter.set_limit(tenant, endpoint, n)`
    与 `QuotaLimiter(limits=...)` 构造参数仍可用，内部等价于落盘一条
    “仅总量层”的持久化策略（现在重启也不丢）；
  - 只配总量上限时行为与上一版一致：凭证/权限类拒绝不计数，总量并发不超扣。
- 新增能力（默认策略、滚动窗口、判定追溯）通过新接口与新字段提供，
  不影响旧调用方；`Decision` 只新增了可选字段。
- 注：旧版“未配置上限的维度默认放行且不计数”的行为，仅在默认策略也未配置时
  保留；本服务启动即写入 `("*","/data")` 默认总量上限 100，可按需调整或删除。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q        # 运行测试：默认策略生效、策略落盘重启不丢、
                        # 窗口滚动/边界、双层并发竞争不越界、无幽灵计数、
                        # 放行可追溯、链路异常 fail-closed、HTTP 端到端
uv run pytest -s        # 额外查看每条请求的 request_id/命中规则/判定依据日志
uv run uvicorn main:app # 启动服务（可用 GOVERNANCE_DB 环境变量指定数据库路径）
```

手工验证示例：

```bash
TOKEN=$(curl -s -X POST localhost:8000/credentials \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"t1","scopes":["read"],"ttl_seconds":3600}' | jq -r .token)

# 给 t1 的 /data 下发：总量 1000，且每 60 秒最多 100 次
curl -s -X PUT localhost:8000/quota/policies -H 'content-type: application/json' -d '{
  "tenant_id":"t1","endpoint":"/data",
  "total_limit":1000,"window_seconds":60,"window_limit":100}'

# 给所有未单独配置的租户定默认上限（总量 100，每 60 秒最多 20 次）
curl -s -X PUT localhost:8000/quota/policies -H 'content-type: application/json' -d '{
  "tenant_id":"*","endpoint":"/data",
  "total_limit":100,"window_seconds":60,"window_limit":20}'

curl -s localhost:8000/data -H "Authorization: Bearer $TOKEN"     # 响应含 request_id
curl -s localhost:8000/quota/t1?endpoint=/data                    # 生效上限与已用量
curl -s localhost:8000/decisions/<request_id>                     # 判定追溯
curl -s "localhost:8000/audit?tenant_id=t1"                       # 审计流水
```

服务端日志与测试日志都会打印每条请求的 `request_id`、命中的规则
（`rule` / `limiting_layer`）、策略来源与两层用量，即判定依据。
