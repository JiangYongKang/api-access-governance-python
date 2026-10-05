"""HTTP 接口端到端：策略下发、生效状态查询、判定追溯、默认策略约束新租户。"""

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture()
def client(tmp_path):
    db = str(tmp_path / "api.db")
    app = main.create_app(db)  # 每个用例独立数据库，互不串状态
    with TestClient(app) as c:
        yield c


def _issue(client, tenant="t1", scopes=("read",)):
    r = client.post("/credentials",
                    json={"tenant_id": tenant, "scopes": list(scopes),
                          "ttl_seconds": 3600})
    return r.json()["token"]


def test_policy_lifecycle_and_decision_lookup(client):
    # 管理员下发默认策略 + 窗口
    r = client.put("/quota/policies", json={
        "tenant_id": "*", "endpoint": "/data",
        "total_limit": 100, "window_seconds": 60.0, "window_limit": 2})
    assert r.status_code == 200 and r.json()["total_limit"] == 100

    token = _issue(client, "tenant-http")
    h = {"Authorization": f"Bearer {token}"}
    r1 = client.get("/data", headers=h)
    body1 = r1.json()
    assert r1.status_code == 200
    rid1 = body1["request_id"]

    r2 = client.get("/data", headers=h)
    assert r2.status_code == 200
    r3 = client.get("/data", headers=h)
    assert r3.status_code == 429
    err = r3.json()["detail"]
    assert err["reason"] == "rate_limited" and err["limiting_layer"] == "window"

    # 放行请求也能按 request_id 追溯
    snap = client.get(f"/decisions/{rid1}").json()
    assert snap["allowed"] is True and snap["window_limit"] == 2
    assert snap["policy_source"] == "default"

    # 生效状态：真正生效的上限与已用量
    status = client.get("/quota/tenant-http?endpoint=/data").json()
    assert status["policy_source"] == "default"
    assert status["window_used"] == 2 and status["window_limit"] == 2

    # 已落盘策略可列出
    policies = client.get("/quota/policies?endpoint=/data").json()["policies"]
    assert any(p["tenant_id"] == "*" for p in policies)


def test_tenant_policy_override_via_api(client):
    client.put("/quota/policies", json={
        "tenant_id": "*", "endpoint": "/data", "total_limit": 1})
    client.put("/quota/policies", json={
        "tenant_id": "vip", "endpoint": "/data",
        "total_limit": 3, "window_seconds": 10.0, "window_limit": 3})
    token = _issue(client, "vip")
    h = {"Authorization": f"Bearer {token}"}
    for _ in range(3):
        assert client.get("/data", headers=h).status_code == 200
    r = client.get("/data", headers=h)
    assert r.status_code == 429
    # 总量与窗口同时到顶：判定顺序先报告总量层
    assert r.json()["detail"]["reason"] == "quota_exceeded"


def test_invalid_policy_returns_422(client):
    r = client.put("/quota/policies", json={
        "tenant_id": "t", "endpoint": "/data",
        "total_limit": 5, "window_seconds": 0.0, "window_limit": 2})
    assert r.status_code == 422


def test_legacy_limits_endpoint_still_works(client):
    """旧的 PUT /quota/limits 仍可用：仅总量层，且落盘后重启不丢。"""
    r = client.put("/quota/limits",
                   json={"tenant_id": "legacy", "endpoint": "/data", "limit": 1})
    assert r.status_code == 204
    token = _issue(client, "legacy")
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/data", headers=h).status_code == 200
    assert client.get("/data", headers=h).status_code == 429
    policies = client.get("/quota/policies?endpoint=/data").json()["policies"]
    mine = [p for p in policies if p["tenant_id"] == "legacy"]
    assert len(mine) == 1 and mine[0]["total_limit"] == 1
    assert mine[0]["window_limit"] is None
