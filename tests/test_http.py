"""HTTP 层端到端测试：错误分类状态码、结构化响应与审计查询。"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GOVERNANCE_DIR", str(tmp_path))
    import main
    importlib.reload(main)  # 使全局 service 基于本用例的临时目录重建
    with TestClient(main.app) as c:
        yield c


def _issue(client: TestClient, tenant: str, scopes: list[str], ttl=None):
    payload = {"tenant": tenant, "scopes": scopes}
    if ttl is not None:
        payload["ttl_seconds"] = ttl
    r = client.post("/admin/credentials", json=payload)
    assert r.status_code == 201, r.text
    return r.json()["credential_id"], r.json()["token"]


def test_error_classification_status_codes(client: TestClient) -> None:
    # 缺凭证 401
    r = client.get("/tenant/data")
    assert r.status_code == 401
    assert r.json()["error"] == "missing_credential"

    # 坏格式 / 权限不足 / 配额超限 / 撤销 都是 403 但 error 可区分
    cid, tok = _issue(client, "tA", ["read:data"])
    _, bad_scopes = _issue(client, "tA", ["nope"])
    r = client.get("/tenant/data", headers={"Authorization": "junk"})
    assert r.status_code == 403 and r.json()["error"] == "untrusted_format"
    r = client.get("/tenant/data", headers={"Authorization": bad_scopes})
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope"

    client.put(
        "/admin/quotas",
        json={"tenant": "tA", "endpoint": "GET /tenant/data",
              "limit": 1, "window_seconds": 3600},
    )
    r = client.get("/tenant/data", headers={"Authorization": tok,
                                            "x-request-id": "q-1"})
    assert r.status_code == 200
    r = client.get("/tenant/data", headers={"Authorization": tok,
                                            "x-request-id": "q-2"})
    assert r.status_code == 403 and r.json()["error"] == "quota_exceeded"
    assert r.json()["request_id"] == "q-2"
    assert r.json()["rule"] == "quota.limit"

    client.post(f"/admin/credentials/{cid}/revoke", json={})
    r = client.get("/tenant/data", headers={"Authorization": tok})
    assert r.status_code == 403 and r.json()["error"] == "revoked_credential"


def test_rotation_grace_over_http(client: TestClient) -> None:
    old_id, old_tok = _issue(client, "tB", ["read:data"])
    r = client.post(
        f"/admin/credentials/{old_id}/rotate", json={"grace_period": 3600}
    )
    assert r.status_code == 200
    new_tok = r.json()["token"]
    # 兼容窗口内旧凭证仍可用
    assert client.get("/tenant/data",
                      headers={"Authorization": old_tok}).status_code == 200
    assert client.get("/tenant/data",
                      headers={"Authorization": new_tok}).status_code == 200


def test_audit_query_endpoint(client: TestClient) -> None:
    _cid, tok = _issue(client, "tC", ["read:data"])
    client.get("/tenant/data", headers={"Authorization": tok,
                                        "x-request-id": "trace-1"})
    r = client.get("/admin/audit", params={"request_id": "trace-1"})
    entries = r.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["decision"] == "allow"
    assert entries[0]["rule"] == "authorize.allow"
    assert entries[0]["tenant"] == "tC"

    r = client.get("/admin/audit", params={"decision": "credential_issued"})
    assert len(r.json()["entries"]) == 1
