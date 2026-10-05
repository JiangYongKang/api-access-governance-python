# API Access Governance

基于 FastAPI 的本地 HTTP 服务，提供多租户访问控制与配额治理能力。所有状态
（凭证、配额用量、审计流水）持久化在本地 SQLite（默认 `governance.db`），
重启后判定结论保持一致。

## 授权模型

- **凭证**：`POST /credentials` 签发，绑定 `tenant_id` 与权限范围（scopes）。
  Token 格式为 `v1.<key_id>.<sig>`，`sig = HMAC-SHA256(secret, key_id)[:32]`；
  无法解析、key_id 未知或签名不匹配的 token 一律视为不可信并拒绝。
- **判定顺序**（短路）：凭证解析 → 权限范围检查 → 配额原子判定（总量层 +
  滚动窗口层，放行计数与放行审计同事务）→ 审计留痕。
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
| `quota_exceeded` | 超出**总量**配额 | 429 |
| `quota_window_exceeded` | 超出**滚动时间窗口**配额 | 429 |
| `quota_unavailable` | 配额策略/记账链路故障，请求被拒绝（绝不静默放行） | 503 |
| `audit_failure` | 审计写入失败，请求被拒绝（绝不静默放行） | 403 |

每次判定（放行或拒绝）的响应体都含 `request_id`、`reason` 与判定快照 `snapshot`
（命中策略来源、各层上限与当时用量），拒绝另含可读的 `detail`，并写入审计流水。

## 轮换与兼容窗口

- `POST /credentials/{key_id}/rotate`：签发同租户、同 scopes 的新凭证；
  旧凭证进入兼容窗口（默认 30 秒，`CredentialManager(grace_seconds=...)` 可调）。
  窗口内旧 token 仍被接受——保证轮换前已发出的在途请求语义确定；
  窗口结束后旧 token 按 `credential_expired` 拒绝。
- `POST /credentials/{key_id}/revoke`：撤销立即生效并终止兼容窗口，
  此后旧 token 一律按 `credential_revoked` 拒绝。

## 配额策略与默认策略

配额策略按 `(tenant_id, endpoint)` 维度**持久化在 SQLite**（表 `quota_policies`），
重启后不丢、不用重新下发。

- **下发/调整**：`PUT /quota/policies`
  ```json
  {
    "tenant_id": "t1",
    "endpoint": "/data",
    "total_limit": 1000,
    "window_limit": 10,
    "window_seconds": 60
  }
  ```
  - `tenant_id="*"` 表示**默认策略**：该 endpoint 下没有精确策略的所有租户都受它约束。
  - `total_limit`：生命周期总量上限；省略（null）表示该层不限。
  - `window_limit` + `window_seconds`：滚动窗口“每 N 秒最多 M 次”；两者必须
    成对出现，省略表示该层不限。
- **生效优先级**：精确策略 `(tenant, endpoint)` 优先；没有精确策略时回退到
  默认策略 `("*", endpoint)`；两者都没有时该维度完全不限。
- **反复下发是确定的覆盖语义**：同一 `(tenant_id, endpoint)` 重复 PUT 以
  最后一次为准（`updated_at` 单调写入），无论调高、调低还是增删窗口层，
  旧策略都不会残留生效；进程重启后生效的仍是最后一条。
- **查询真正生效的上限与已用量**：
  `GET /quota/status?tenant_id=t1&endpoint=/data`，返回 `policy_source`
  （`exact` / `default` / `none`）、总量/窗口两层的 `limit` 与当前 `used`。
- 首次启动会为 `/data` 幂等种入一条默认总量策略（100，仅当尚无默认策略时；
  之后管理员调整的值会被保留，重启不会被种子覆盖）。

### 总量层与滚动窗口层叠加语义

一条策略可以同时配置两层，判定时在**单存储事务**内同时检查，任一层到顶即拒绝，
并明确返回是被哪一层拦下的：

- 总量先到顶 → `quota_exceeded`（429）；
- 窗口先到顶（或两层同时到顶时总量优先）→ `quota_window_exceeded`（429）。
- **滚动窗口**是半开区间：时刻 `now` 的窗口内事件为 `ts > now - window_seconds`，
  窗口随时间自然滑动、自动重置，无需手工清零；窗口事件同样持久化，重启后
  窗口判定连续。跨过窗口边界的请求按上述不等式得到稳定、可解释的结论。
- **原子性 / 无幽灵计数**：总量检查扣减、窗口过期事件清理、窗口事件插入都在
  单锁单事务内完成。并发请求不会突破任何一层；被拒绝的请求不写任何计数
  （不会出现“请求没被放行却吃掉次数”）。
- **放行即可追溯**：放行请求的计数与一条 `access_allowed` 审计在同一事务内
  提交（要么都成功，要么都回滚），审计 extra 含命中策略、策略来源以及当时
  两层的用量/上限快照；拒绝请求写 `access_denied`。所有判定都能用
  `GET /audit?request_id=<id>` 按请求标识查到。
- **Fail-closed**：策略读取、记账或审计链路异常时，请求一律拒绝
  （`quota_unavailable` 503 / `audit_failure` 403），绝不因链路异常静默放行。

### 兼容范围（旧用法仍然可用）

- 旧接口 `PUT /quota/limits {tenant_id, endpoint, limit}` 保留：只覆盖总量层，
  该维度已有的窗口配置会被保留。
- 旧查询 `GET /quota/{tenant_id}` 保留：返回总量已用。
- 行为差异提示：旧实现的上限只存在进程内存里、重启丢失，且未配置即完全不限；
  现在 `set_limit`/旧接口写入的是持久化策略，且会命中默认策略。
  库层若既不下发精确策略、也不种默认策略，则仍是“完全不限、不计数”，
  与旧语义一致。
- 代码层 `QuotaLimiter.try_acquire()` / `set_limit()` / `usage()` 保留，
  但 `try_acquire` 内部已走新的双层原子判定（含窗口层）。

## 审计流水

- 事件：`access_allowed`（放行：命中策略、策略来源、两层用量/上限快照）、
  `access_denied`（拒绝：判定依据、拒绝层与用量快照）、
  `credential_issued`、`credential_rotated`、`credential_revoked`、
  `quota_policy_set`（管理员下发/调整策略的留痕）。
- 放行审计与配额两层计数在同一事务内提交，并发下不丢失、不重复
  （`seq` 自增唯一）；链路异常时整体回滚并拒绝请求。
- 审计写入失败时，授权结论为 `audit_failure` 拒绝，不会静默放行。
- 查询：`GET /audit?tenant_id=...&event=...&request_id=...`，
  可直接按请求标识追溯单笔判定。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q        # 运行测试（默认策略生效、策略/窗口落盘重启不丢、
                        # 多窗口与总量并发竞争不越界、窗口滚动与边界、
                        # 放行可追溯、链路异常 fail-closed、凭证生命周期）
uv run uvicorn main:app # 启动服务
```

手工验证示例：

```bash
TOKEN=$(curl -s -X POST localhost:8000/credentials \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"t1","scopes":["read"],"ttl_seconds":3600}' | jq -r .token)

# 下发“总量 1000 + 每 60 秒最多 10 次”的策略（tenant_id 换成 "*" 即默认策略）
curl -s -X PUT localhost:8000/quota/policies -H 'content-type: application/json' -d '{
  "tenant_id":"t1","endpoint":"/data",
  "total_limit":1000,"window_limit":10,"window_seconds":60}' -o /dev/null -w '%{http_code}\n'

# 查看当前真正生效的上限与已用量（policy_source=exact/default/none）
curl -s "localhost:8000/quota/status?tenant_id=t1&endpoint=/data" | jq

curl -s localhost:8000/data -H "Authorization: Bearer $TOKEN" | jq
# 按请求标识追溯这一笔判定命中了哪条策略、当时用量/上限是多少
RID=$(curl -s localhost:8000/data -H "Authorization: Bearer $TOKEN" | jq -r .request_id)
curl -s "localhost:8000/audit?request_id=$RID" | jq
```

重启服务（`uv run uvicorn main:app`）后无需重新下发：策略、总量用量与窗口
事件都从 `governance.db` 恢复，判定按同一套规则继续。

测试日志会打印每条请求的 `request_id`、命中的规则（`reason`）与判定依据
（`detail`），可用 `uv run pytest -s` 查看。
