"""RFC 9421 HTTP 消息签名（Ed25519 子集）与 RFC 9530 内容摘要核验。

本模块只负责线路上的事实核验：
- 验签必须基于请求实际交付的原始字节，正文不得先重排；
- 签名基底按 Signature-Input 实际列出的分量重建，覆盖请求目标、
  正文摘要以及这一次投递（notification-id）；
- 转递消息的内层成员签名按其原始 JSON 字节独立核验；
- 收件端控制声明使用与转递内层相同的“签名 + 原始字节”材料格式。

业务上的登记、授权与对账判断放在 :mod:`desk`。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

__all__ = [
    "WireError",
    "SignatureInfo",
    "verify_request",
    "verify_signed_bytes",
    "content_digest",
    "reconstruct_signature_base",
]

# 只接受资料约定的确定性子集。
ALLOWED_ALG = "ed25519"
REQUIRED_COMPONENTS = ("@method", "@target-uri", "content-digest", "notification-id")
_LABEL_RE = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]+")


class WireError(ValueError):
    """线路材料无法通过签名或摘要核验。"""


@dataclass(frozen=True)
class SignatureInfo:
    """一次成功验签后得到的签名身份与覆盖范围。"""

    label: str
    keyid: str
    alg: str
    created: int | None
    components: tuple[str, ...]

    def covers_required_subset(self) -> bool:
        """签名是否实际保护请求目标、正文与本次投递。"""
        return all(component in self.components for component in REQUIRED_COMPONENTS)


def _b64(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:  # pragma: no cover - 防御性分支
        raise WireError("base64 解码失败") from exc


def content_digest(body: bytes) -> str:
    """按 RFC 9530 生成 sha-256 Content-Digest 字段值。"""
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{digest}:"


def _parse_signature_input(value: str) -> tuple[str, tuple[str, ...], dict[str, str]]:
    """解析 `label=("c1" "c2");created=..;keyid="..";alg=".."`。"""
    if "=" not in value:
        raise WireError("Signature-Input 缺少标签")
    label, rest = value.split("=", 1)
    label = label.strip()
    if not _LABEL_RE.fullmatch(label):
        raise WireError("非法的签名标签")
    if not rest.startswith("("):
        raise WireError("Signature-Input 缺少分量列表")
    close = rest.index(")")
    covered = tuple(re.findall(r'"([^"]+)"', rest[:close]))
    if not covered:
        raise WireError("签名未覆盖任何分量")
    params: dict[str, str] = {}
    for param in rest[close + 1 :].split(";"):
        param = param.strip()
        if not param:
            continue
        if "=" not in param:
            raise WireError(f"签名参数缺少取值: {param}")
        name, raw = param.split("=", 1)
        params[name.strip()] = raw.strip().strip('"')
    return label, covered, params


def _parse_signature(value: str, label: str) -> bytes:
    prefix = f"{label}=:"
    if not value.startswith(prefix) or not value.endswith(":"):
        raise WireError("Signature 与 Signature-Input 标签不一致")
    return _b64(value[len(prefix) : -1])


def reconstruct_signature_base(request: Mapping) -> bytes:
    """按 RFC 9421 第 2.5 节从请求重建签名基底（含 @signature-params）。"""
    headers = request["headers"]
    try:
        input_value = headers["signature-input"]
    except KeyError as exc:
        raise WireError("缺少 Signature-Input") from exc
    label, components, params = _parse_signature_input(input_value)
    lines: list[str] = []
    for component in components:
        if component == "@method":
            lines.append(f'"@method": {request["method"]}')
        elif component == "@target-uri":
            lines.append(f'"@target-uri": {request["target_uri"]}')
        elif component.startswith('"'):  # pragma: no cover
            raise WireError(f"不支持的分量: {component}")
        else:
            # HTTP 字段名不区分大小写，资料统一使用小写键。
            if component not in headers:
                raise WireError(f"签名分量在请求中缺失: {component}")
            lines.append(f'"{component}": {headers[component]}')
    param_text = input_value[input_value.index(")") + 1 :]
    params_rendered = " ".join(f'"{c}"' for c in components)
    lines.append(f'"@signature-params": ({params_rendered}){param_text}')
    return "\n".join(lines).encode("utf-8")


def verify_request(request: Mapping, public_keys: Mapping[str, object]) -> SignatureInfo:
    """核验整条 HTTP 请求的内容摘要与消息签名。

    `public_keys` 把 keyid 映射到已加载的公钥对象（或 PEM 字节）。
    成功时返回 :class:`SignatureInfo`；任何一项失败都抛出 :class:`WireError`。
    """
    headers = request["headers"]
    body = _b64(request["body"])

    # 1. 正文摘要：必须对发送方实际交付的原始字节计算，不能先 json 重排。
    if headers.get("content-digest") != content_digest(body):
        raise WireError("Content-Digest 与实际正文不一致")

    # 2. 解析签名输入，强制约定子集。
    label, components, params = _parse_signature_input(headers["signature-input"])
    alg = params.get("alg")
    if alg != ALLOWED_ALG:
        raise WireError(f"不支持的 alg: {alg!r}")
    keyid = params.get("keyid")
    if not keyid:
        raise WireError("Signature-Input 缺少 keyid")
    if keyid not in public_keys:
        raise WireError(f"keyid 未登记: {keyid}")
    created_raw = params.get("created")
    created = int(created_raw) if created_raw is not None else None

    # 3. 用同一标签取 Signature，重建基底并验签。
    signature = _parse_signature(headers["signature"], label)
    base = reconstruct_signature_base(request)
    key = public_keys[keyid]
    if isinstance(key, (bytes, bytearray)):
        key = load_pem_public_key(bytes(key))
    try:
        key.verify(signature, base)
    except InvalidSignature as exc:
        raise WireError("消息签名核验失败") from exc

    info = SignatureInfo(label, keyid, alg, created, components)
    if not info.covers_required_subset():
        raise WireError("签名未覆盖请求目标、正文摘要或本次投递标识")
    return info


def verify_signed_bytes(material: Mapping, public_keys: Mapping[str, object]) -> dict:
    """核验转递内层或收件控制声明这类独立签名材料。

    材料格式为 ``{"keyid", "signature", "signed_bytes"}``（收件控制声明的
    外层字段名相同），对 ``signed_bytes`` 的原始字节直接验签，返回解析后的
    JSON 声明；声明字节原样保留，调用方可以据此留档。
    """
    keyid = material.get("keyid")
    if not keyid or keyid not in public_keys:
        raise WireError(f"内层签名 keyid 未登记: {keyid!r}")
    raw = _b64(material["signed_bytes"])
    signature = _b64(material["signature"])
    key = public_keys[keyid]
    if isinstance(key, (bytes, bytearray)):
        key = load_pem_public_key(bytes(key))
    try:
        key.verify(signature, raw)
    except InvalidSignature as exc:
        raise WireError("内层签名核验失败") from exc
    try:
        claim = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WireError("内层签名字节不是合法 JSON 声明") from exc
    if not isinstance(claim, dict):
        raise WireError("内层声明必须是 JSON 对象")
    return claim
