# API 访问治理（本地多租户凭证 / 配额 / 审计）

为本地 HTTP 服务提供一套**多租户访问控制与配额治理**能力。凭证、配额与
审计状态全部保存在本地文件，不依赖任何外部服务；核心目标是让**并发请求、
凭证轮换与异常链路下的判定结论一致且可解释**。

- 凭证：带租户与权限范围（scope）的本地凭证签发、轮换、撤销；只存哈希不存明文。
- 配额：按 `(租户, 接口)` 维度的固定窗口计数限流，拒绝永不计数，可持久化。
- 审计：放行、拒绝与凭证变更全部落 JSONL 流水，含请求标识、命中规则与依据；
  审计异常时 **fail-closed**（拒绝放行），绝不静默通过。

---

## 1. 目录结构

```
governance/
  errors.py        # 稳定错误码 DenyReason 与结构化 GovernanceError
  model.py         # CredentialRecord / AuthDecision / AuditEntry / QuotaState
  tokens.py        # 本地凭证格式、解析、SHA-256 哈希、常量时间比较
  persistence.py   # 凭证+配额状态：进程内 RLock + 单文件 JSON 原子落盘
  credentials.py   # 签发 / 轮换 / 撤销 / 认证（判定顺序固定）
  quota.py         # 固定窗口配额：evaluate（只读投影）+ commit（提交）
  audit.py         # JSONL 审计流水：锁串行追加、flush+fsync、条件查询
  service.py       # 编排层：认证 → 配额评估 → 审计先行 → 配额提交
main.py            # FastAPI HTTP 入口（管理端 + 受保护接口）
tests/             # 并发竞争 / 在途轮换 / 边界拒绝 / 审计异常 / HTTP 测试
```

本地数据默认写入 `.data/`（可用环境变量 `GOVERNANCE_DIR` 覆盖）：

- `.data/state.json`：凭证与配额状态（原子替换写）。
- `.data/audit.jsonl`：审计流水（每行一条 JSON，仅追加）。

---

## 2. 授权模型

### 2.1 凭证格式

凭证明文仅在签发时返回一次，格式为：

```
lgac_<32位hex凭证id>.<url-safe随机秘密>
```

服务端只保存随机秘密的 SHA-256。凭证通过 HTTP 头
`Authorization: lgac_...` 原样传递（本地演示，不使用 Bearer 包装）。

### 2.2 认证判定顺序（先命中先生效，原因稳定可区分）

对每个受保护请求，`CredentialService.authenticate` 严格按以下顺序判定：

| 顺序 | 命中规则 `rule` | 错误码 `error` | 含义 |
|---:|---|---|---|
| 1 | `credential.present` | `missing_credential` | 未携带凭证 |
| 2 | `credential.format` | `untrusted_format` | 前缀/分段/id 长度或字符集不可信 |
| 3 | `credential.exists` | `unknown_credential` | id 在服务端无记录 |
| 4 | `credential.revoked` | `revoked_credential` | 已撤销且不在兼容窗口内 |
| 5 | `credential.expires_at` | `expired_credential` | 超过凭证自身有效期 |
| 6 | `credential.grace_window_closed` | `expired_credential` | 旧凭证轮换兼容窗口已结束 |
| 7 | `credential.secret` | `untrusted_format` | 哈希不匹配（伪造/截断） |
| 8 | `credential.scope` | `insufficient_scope` | 权限范围不含所需 scope |
| — | `credential.ok` / `authorize.allow` | （放行） | 认证与配额均通过 |

### 2.3 一次授权的完整顺序（service.authorize）

全部步骤在 `GovernanceStore` 的同一把 `RLock` 临界区内完成：

1. **认证 + scope 检查**。失败 → 写拒绝审计 → 抛错；不触碰配额。
2. **配额只读评估** `QuotaManager.evaluate`：只在内存里做窗口滚动与 `+1`
   投影，不修改状态、不落盘。超限 → 写拒绝审计 → 抛 `quota_exceeded`。
3. **先写放行审计并 `fsync`，再提交配额** `QuotaManager.commit`（提交时
   重新读状态演算并校验，防止超卖）。
4. 任一步骤失败：审计没成功就不提交配额；结论恒为拒绝。

因此“**审计中的放行记录数 == 配额 used 增量 == 实际放行数**”三者严格一致。

---

## 3. 配额语义

- 维度：`(tenant, endpoint)`；未配置配额的维度**视为不限流**（不入库、不计数）。
- 算法：**固定窗口**。窗口区间为 `[window_start, window_start + window_seconds)`；
  进入新区间时计数清零、窗口起点对齐到当前时刻。
- **无幽灵配额**：认证/授权被拒绝的请求不会进入配额评估；配额在审计落盘
  成功后才提交。被限流的请求 `used` 不增加。
- **不超卖**：评估是纯函数投影，提交时重新读取当前状态校验
  （`base+1 == projected` 且窗口一致），配合全局锁，N 并发 / 上限 L 时
  放行数严格等于 `min(N, L)`（见 `tests/test_quota_concurrency.py`）。
- **可持久化**：每次提交都原子落盘；进程重启后在同一窗口内沿用 `used` 与
  `window_start`，结论不变。
- 修改 `limit` / `window_seconds` 不会重置当前窗口用量（避免改配置绕过限流）。

---

## 4. 轮换、撤销与兼容窗口（在途请求语义）

所有凭证状态变更与请求判定共用同一把锁，因此一个请求的结论只取决于它
**进入临界区时读到的状态**，可复现、无竞态歧义。

### 4.1 轮换 `POST /admin/credentials/{id}/rotate`

- 生成**新凭证 id 与新随机秘密**（version + 1），旧凭证记录保留，
  设置 `grace_until = now + grace_period`，并记录 `superseded_by`。
- 兼容窗口 `[now, grace_until)` 内，持有旧凭证的**在途请求继续放行**
  （认证规则仍为 `credential.ok`）；新凭证立即可用。
- 窗口结束后旧凭证以稳定组合被拒绝：
  `error=expired_credential`、`rule=credential.grace_window_closed`。
- `grace_period=0`（默认）时旧凭证在下一次请求即按窗口结束拒绝。

### 4.2 撤销 `POST /admin/credentials/{id}/revoke`

- 设置 `revoked_at`，凭证立即失效。
- `grace_period=0`（默认）：撤销落盘之后进入临界区的请求**一律**
  `error=revoked_credential, rule=credential.revoked`。
- `grace_period>0`：窗口内的在途请求确定放行，窗口结束后按撤销拒绝
  （撤销判定优先于过期/窗口规则）。
- 已撤销凭证不能再被轮换。

> 说明：本实现的“在途”指已到达服务端、等待进入或正在临界区内判定的请求。
> 撤销/轮换与判定在同一把锁上串行，故不存在“判定读到一半状态”的窗口。

---

## 5. 审计流水

- 文件：`.data/audit.jsonl`，每行一条 JSON；进程内一把锁串行追加，
  追加后 `flush + fsync`；并发写入不丢失、不重复（有测试校验 100 并发
  追加 100 条、id 唯一）。
- `decision` 取值：`allow` / `deny` / `credential_issued` /
  `credential_rotated` / `credential_revoked`。
- 每条记录含：`request_id`、`timestamp`、`tenant`、`endpoint`、命中的
  `rule`、拒绝 `reason`、文字 `detail`、`credential_id`，以及拒绝/放行时
  的 `quota_used` / `quota_limit`。
- 查询：`GET /admin/audit?tenant=&request_id=&decision=&limit=`（倒序）。
- **审计异常 fail-closed**：放行路径审计写失败 →
  `error=audit_failure, rule=audit.append`（HTTP 500），且不提交配额；
  拒绝路径审计也失败时，错误升级为 `audit_failure`，请求维持拒绝。

---

## 6. 错误分类（HTTP）

所有拒绝统一返回：

```json
{ "error": "<稳定错误码>", "rule": "<命中规则>", "detail": "<判定依据>", "request_id": "<请求标识>" }
```

| error | HTTP 状态码 | 触发场景 |
|---|---:|---|
| `missing_credential` | 401 | 未带凭证 |
| `untrusted_format` | 403 | 格式不可信 / 秘密不匹配 |
| `unknown_credential` | 403 | 凭证 id 无记录 |
| `revoked_credential` | 403 | 已撤销（兼容窗口外） |
| `expired_credential` | 403 | 自身过期 / 轮换兼容窗口结束 |
| `insufficient_scope` | 403 | scope 不足 |
| `quota_exceeded` | 403 | 配额耗尽（detail 含 used/limit/窗口） |
| `audit_failure` | 500 | 审计/提交链路异常，安全拒绝 |

请求标识来源：请求头 `x-request-id`；未提供时服务端生成 `req-<uuid>`。

---

## 7. HTTP 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 健康检查 |
| POST | `/admin/credentials` | 签发 `{tenant, scopes:[], ttl_seconds?}` |
| POST | `/admin/credentials/{id}/rotate` | 轮换 `{grace_period?}` |
| POST | `/admin/credentials/{id}/revoke` | 撤销 `{grace_period?}` |
| GET | `/admin/credentials?tenant=` | 列凭证（不返回秘密/哈希） |
| PUT | `/admin/quotas` | 配配额 `{tenant, endpoint, limit, window_seconds}` |
| GET | `/admin/quotas?tenant=&endpoint=` | 查配额 |
| GET | `/admin/audit?tenant=&request_id=&decision=&limit=` | 查审计 |
| GET | `/tenant/data` | 受保护接口（需 `read:data`，计入配额） |

---

## 8. 本地验证方法

### 8.1 运行测试

```bash
uv sync
uv run pytest                      # 全部 21 个用例，日志含 request_id/规则/依据
```

重点用例：

- `tests/test_quota_concurrency.py`
  - `test_concurrent_requests_never_exceed_limit`：200 并发 / 上限 50，
    断言放行数=50、拒绝数=150、`used=50`、审计 allow=50 且 id 一一对应。
  - `test_denied_requests_have_no_ghost_quota`：缺凭证/坏格式/scope 不足
    一律不消耗配额。
  - `test_quota_persists_across_restart`：重启后同窗口继续限流。
  - `test_fixed_window_rolls_over`：拨时钟验证固定窗口滚动。
- `tests/test_inflight_rotation.py`：轮换/撤销与 20 个在途请求并发冲线，
  断言窗口内旧凭证全放行、立即撤销后全部 `revoked_credential`、审计无重复丢失。
- `tests/test_credentials.py`：8 类拒绝原因可区分、过期/撤销/宽限窗口、重启一致。
- `tests/test_audit_failure.py`：审计磁盘故障时 fail-closed 且无幽灵配额。
- `tests/test_http.py`：状态码与结构化错误响应、轮换宽限、审计查询。

### 8.2 手工 curl 演示

```bash
uv run uvicorn main:app --reload

# 1) 签发凭证
curl -s -X POST localhost:8000/admin/credentials \
  -H 'content-type: application/json' \
  -d '{"tenant":"acme","scopes":["read:data"]}'

# 2) 配置配额：每 3600s 2 次
curl -s -X PUT localhost:8000/admin/quotas \
  -H 'content-type: application/json' \
  -d '{"tenant":"acme","endpoint":"GET /tenant/data","limit":2,"window_seconds":3600}'

# 3) 访问受保护接口（前两次 200，第三次 403 quota_exceeded）
curl -i localhost:8000/tenant/data -H 'authorization: lgac_xxx.yyy' \
  -H 'x-request-id: demo-1'

# 4) 轮换（旧凭证 60s 兼容窗口）
curl -s -X POST localhost:8000/admin/credentials/<id>/rotate \
  -H 'content-type: application/json' -d '{"grace_period":60}'

# 5) 撤销（立即生效）
curl -s -X POST localhost:8000/admin/credentials/<id>/revoke \
  -H 'content-type: application/json' -d '{}'

# 6) 查审计
curl -s 'localhost:8000/admin/audit?request_id=demo-1'
```

### 8.3 设计要点小结（为什么结论一致）

1. **一把锁**：凭证、配额状态共用 `RLock`，认证/配额/落盘与轮换/撤销互斥。
2. **两阶段配额**：只读投影 → 审计 fsync → 重新演算提交，杜绝超卖与幽灵配额。
3. **原子落盘**：状态写临时文件后 `os.replace`；崩溃只会读到旧/新版本之一。
4. **稳定判定表**：拒绝原因与规则标识是固定枚举与字符串，测试按组合断言。
5. **fail-closed**：任何审计/存储异常都转化为明确拒绝而非放行。
