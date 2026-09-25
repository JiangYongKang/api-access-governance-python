"""凭证字符串的签发、解析与哈希（本地可信格式）。

凭证明文格式（仅本地使用）::

    lgac_<credential_id>.<随机秘密>

服务端只保存随机秘密的 SHA-256 哈希；任何不符合该格式或解析失败的
凭证一律按 :data:`DenyReason.UNTRUSTED_FORMAT` 拒绝。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

from governance.errors import DenyReason, GovernanceError

_PREFIX = "lgac_"


def generate_credential_id() -> str:
    """生成全局唯一凭证 id（32 位十六进制）。"""
    return uuid.uuid4().hex


def generate_token(credential_id: str) -> str:
    """为凭证 id 生成一个全新的凭证明文。"""
    if not credential_id:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="credential_id 不能为空",
        )
    return f"{_PREFIX}{credential_id}.{secrets.token_urlsafe(32)}"


def parse_token(token: str) -> str:
    """解析凭证明文，返回 credential_id。

    格式不可信时抛出 ``GovernanceError(UNTRUSTED_FORMAT)``。

    判定规则 ``credential.format``：必须以 ``lgac_`` 开头，且恰好由
    "凭证 id" 与 "随机秘密" 两段组成，两段均非空，id 必须是 32 位
    十六进制字符。
    """
    if not isinstance(token, str) or not token:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="凭证为空或不是字符串",
        )
    if not token.startswith(_PREFIX):
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail=f"凭证必须以 {_PREFIX!r} 前缀开头",
        )
    body = token[len(_PREFIX) :]
    parts = body.split(".")
    if len(parts) != 2:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="凭证必须恰好包含一个 '.' 分隔符",
        )
    credential_id, secret = parts
    if not credential_id or not secret:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="凭证 id 与随机秘密均不得为空",
        )
    if len(credential_id) != 32:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="凭证 id 长度必须为 32 位十六进制字符",
        )
        # 防御：hex 校验放在长度校验之后，保证原因稳定可复现
    try:
        int(credential_id, 16)
    except ValueError:
        raise GovernanceError(
            DenyReason.UNTRUSTED_FORMAT,
            rule="credential.format",
            detail="凭证 id 必须为十六进制字符",
        ) from None
    return credential_id


def hash_token(token: str) -> str:
    """计算凭证明文的服务端存储哈希。"""
    return _sha256(token)


def constant_time_equals(a: str, b: str) -> bool:
    """常量时间字符串比较，避免哈希比对侧信道。"""
    return hmac.compare_digest(a, b)


def _sha256(text: str) -> str:
    """内部工具：SHA-256 十六进制摘要。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
