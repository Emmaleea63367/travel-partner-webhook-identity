"""联票回调收件、身份授权与核账台规则。

核账台把三件事分开记账，互不替代：

1. 谁实际发了消息——由 HTTP 消息签名（:mod:`wireverify`）核验实际签发者；
2. 谁有权声明这笔款——成员自签，或登记过、作用域匹配的合办机构转递成员
   已签声明（两层身份各自核验）；代办进度通知不产生成员事实；
3. 这条消息进入哪个收件端——按收件端当期控制身份与控制窗口认定，同址换
   承办者后，旧投递与新投递分别留痕、不得合并。

只有各应结算方独立证明其负责的结果、且相关投递确认齐备时，联票才结清；
通知仅投递、代理人仅反馈进度、迟到回执或事实缺失时，票款一律列为待核。
"""
from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from wireverify import WireError, verify_request, verify_signed_bytes

ROOT = Path(__file__).resolve().parent
MATERIALS = ROOT / "materials"
WIRE = ROOT / "wire"

FACT_KINDS = ("redeemed", "reversed")
AUDITOR = "auditor"


class DeskError(ValueError):
    """核账台规则被违反（越权、错投或交接不合规）。"""


@dataclass(frozen=True)
class AttestedMessage:
    """通过线路核验后进入台账的一条通知及其身份结论。"""

    message_id: str
    keyid: str
    kind: str
    auth_path: str  # direct | relay | progress | rejected
    member: str
    route: str
    line: str | None
    revision: int | None
    delegate_id: str | None
    basis: str  # 原始正文 Base64，留档所据
    note: str = ""


@dataclass
class LineStatus:
    line: str
    ticket: str
    member: str
    route: str
    net_cents: int
    current: dict | None = None
    history: list[dict] = field(default_factory=list)
    delivery: dict[str, str] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def fact_confirmed(self) -> bool:
        return self.current is not None and self.current["kind"] == "redeemed"

    @property
    def settled(self) -> bool:
        return self.fact_confirmed and not self.reasons

    @property
    def pending_cents(self) -> int:
        return 0 if self.settled else self.net_cents


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _index(rows: list[dict], key: str = "id") -> dict[str, dict]:
    return {row[key]: row for row in rows}


class ReconciliationDesk:
    """从登记资料与线路材料构建可重复执行的核账结论。"""

    def __init__(self, materials_dir: Path = MATERIALS, wire_dir: Path = WIRE):
        self.materials_dir = Path(materials_dir)
        self.wire_dir = Path(wire_dir)
        self.members = _index(_load_json(self.materials_dir / "members.json"))
        self.delegates = _load_json(self.materials_dir / "delegates.json")
        self.endpoints = _index(_load_json(self.materials_dir / "endpoints.json"))
        self.ownership = _index(_load_json(self.materials_dir / "endpoint_ownership.json"))
        self.lines = _index(_load_json(self.materials_dir / "lines.json"))
        self.delivery_rows = _load_json(self.materials_dir / "delivery.json")
        self.requests = _load_json(self.wire_dir / "requests.json")
        self.controls_raw = _load_json(self.wire_dir / "receive-control.json")
        self.public_keys = {
            path.stem: load_pem_public_key(path.read_bytes())
            for path in self.wire_dir.glob("*.pub")
        }
        self._member_by_key = {m["key"]: mid for mid, m in self.members.items()}
        self.messages: dict[str, AttestedMessage] = {}
        self.rejected: list[dict] = []
        self.controls: dict[str, dict] = {}
        self.delivery: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------ 登记
    def _delegate_grants(self, keyid: str, member: str, route: str) -> list[dict]:
        return [
            d
            for d in self.delegates
            if d["key"] == keyid and d["member"] == member and d["route"] == route
        ]

    def _assert_member_scope(self, member_id: str, route: str):
        member = self.members.get(member_id)
        if member is None:
            raise DeskError(f"成员未登记: {member_id}")
        if route not in member["routes"]:
            raise DeskError(f"成员 {member_id} 未获授权线路 {route}")

    def _assert_line_binding(self, claim: Mapping, member_id: str, route: str):
        line = self.lines.get(claim.get("line", ""))
        if line is None:
            raise DeskError(f"票行不存在: {claim.get('line')!r}")
        if line["member"] != member_id or line["route"] != route:
            raise DeskError(
                f"声明票行 {line['id']} 与签名身份 {member_id}/{route} 不绑定"
            )

    # ------------------------------------------------------------ 收件端控制
    def verify_endpoint_controls(self) -> dict[str, dict]:
        """核验新旧收件端持有者的控制身份声明。

        声明按 endpoint_ownership 登记的收件公钥验签，并核对绑定端点、
        承办者、目标地址与控制窗口；同址不同承办者分别成立、互不继承。
        """
        for material in self.controls_raw:
            claim = verify_signed_bytes(material, self.public_keys)
            keyid = material["keyid"]
            endpoint = self.endpoints.get(claim["binding"])
            owner = next(
                (o for o in self.ownership.values() if o["endpoint"] == claim["binding"]),
                None,
            )
            if endpoint is None or owner is None:
                raise DeskError(f"控制声明引用未知收件端: {claim['binding']}")
            if owner["key"] != keyid or owner["holder"] != endpoint["controller"]:
                raise DeskError(f"控制身份与登记不一致: {keyid}")
            if endpoint["controller"] != owner["holder"]:
                raise DeskError(f"承办者与端点控制登记不一致: {owner['holder']}")
            if endpoint["member"] != claim["operator"]:
                raise DeskError("控制声明代表的运营方与端点登记不符")
            if endpoint["url"] != claim["target"]:
                raise DeskError("控制声明目标地址与端点登记不符")
            at = claim["at"]
            if at < owner["from_time"] or not (
                endpoint["from_time"] <= at < endpoint["until_time"]
            ):
                raise DeskError(f"控制声明时刻 {at} 不在 {endpoint['id']} 控制窗口内")
            self.controls[endpoint["id"]] = {"keyid": keyid, **claim}
        return self.controls

    def _endpoint_at(self, url_or_id: str, at: int) -> dict | None:
        """返回给定时刻控制该地址或端点编号的当期收件端。"""
        for endpoint in self.endpoints.values():
            if endpoint["id"] != url_or_id and endpoint["url"] != url_or_id:
                continue
            if endpoint["from_time"] <= at < endpoint["until_time"]:
                return endpoint
        return None

    # ------------------------------------------------------------- 消息收件
    def ingest(self) -> dict[str, AttestedMessage]:
        """逐条核验并收纳线路消息，给出身份与授权结论。"""
        for request in self.requests:
            msg_id = request["id"]
            try:
                info = verify_request(request, self.public_keys)
                raw = base64.b64decode(request["body"])
                body = json.loads(raw.decode("utf-8"))
                attested = self._classify(msg_id, info.keyid, body, request["body"])
            except (WireError, DeskError, ValueError) as exc:
                attested = AttestedMessage(
                    msg_id,
                    keyid="",
                    kind="",
                    auth_path="rejected",
                    member="",
                    route="",
                    line=None,
                    revision=None,
                    delegate_id=None,
                    basis=request["body"],
                    note=str(exc),
                )
                self.rejected.append({"message": msg_id, "reason": str(exc)})
            self.messages[msg_id] = attested
        return self.messages

    def _classify(self, msg_id: str, keyid: str, body: dict, basis: str) -> AttestedMessage:
        def make(path, member, route, line, revision, kind, delegate_id=None, note=""):
            return AttestedMessage(
                msg_id, keyid, kind, path, member, route, line, revision, delegate_id, basis, note
            )

        # 1. 成员自签：签名身份必须就是声明成员。
        if keyid in self._member_by_key:
            member_id = self._member_by_key[keyid]
            if body.get("member") != member_id:
                raise DeskError("成员签名与其声明的成员身份不一致")
            route = body.get("route", "")
            self._assert_member_scope(member_id, route)
            if body.get("kind") in FACT_KINDS:
                self._assert_line_binding(body, member_id, route)
                return make("direct", member_id, route, body["line"], body["revision"], body["kind"])
            return make(
                "direct", member_id, route, body.get("line"), body.get("revision"),
                str(body.get("kind", "")), note="非成员事实类通知",
            )

        # 2. 合办机构：必须有登记，且只能在授权作用域内动作。
        if not any(d["key"] == keyid for d in self.delegates):
            raise DeskError(f"签名 keyid 既非成员也非登记合办机构: {keyid}")

        # 2a. 转递：外层是机构 HTTP 签名，内层是成员自己的签名，两层各自核验。
        if "forwarded" in body:
            inner = verify_signed_bytes(body["forwarded"], self.public_keys)
            inner_keyid = body["forwarded"]["keyid"]
            member_id = self._member_by_key.get(inner_keyid)
            if member_id is None:
                raise DeskError("转递内层签名不是登记成员身份")
            if inner.get("member") != member_id:
                raise DeskError("内层成员签名与其声明身份不一致")
            route = inner.get("route", "")
            grants = self._delegate_grants(keyid, member_id, route)
            delegate = next((d for d in grants if d["grant"] == "relay"), None)
            if delegate is None:
                raise DeskError(f"合办机构 {keyid} 无 {member_id}/{route} 的 relay 授权")
            self._assert_member_scope(member_id, route)
            if inner.get("kind") not in FACT_KINDS:
                raise DeskError("转递内容不是成员核销/冲销事实")
            self._assert_line_binding(inner, member_id, route)
            return make(
                "relay", member_id, route, inner["line"], inner["revision"],
                inner["kind"], delegate_id=delegate["id"],
                note=f"内层成员签名 {inner_keyid} 与外层机构签名 {keyid} 分别核验",
            )

        # 2b. 代办进度：明示代理，绝不产生成员事实，也不得陈述成员事实。
        if body.get("kind") == "progress":
            member_id = body.get("member", "")
            route = body.get("route", "")
            delegate = next(
                (d for d in self._delegate_grants(keyid, member_id, route)
                 if d["grant"] == "progress"),
                None,
            )
            if delegate is None:
                raise DeskError(f"合办机构 {keyid} 无 {member_id}/{route} 的 progress 授权")
            self._assert_member_scope(member_id, route)
            forbidden = set(FACT_KINDS) | {"settled"}
            if set(body) & forbidden or body.get("declares") in forbidden:
                raise DeskError("代办进度通知不得替成员陈述核销、冲销或结清事实")
            return make(
                "progress", member_id, route, body.get("line"), body.get("revision"),
                "progress", delegate_id=delegate["id"], note="仅代理进度，不形成成员事实",
            )

        raise DeskError("合办机构不得以自身签名替成员宣布核销、冲销或结清事实")

    # ------------------------------------------------------------- 投递认定
    def adjudicate_delivery(self) -> dict[str, list[dict]]:
        """按收件端控制窗口认定每条投递观测。

        - 仅 ``received`` 且回执时间落在持有者控制窗口内才算当期确认交付；
        - 窗口外的补交回执记为迟到回执，只能证明旧持有者过去收到某一版；
        - 同一消息的多次观测、新旧端投递分别留痕，绝不合并。
        """
        self.delivery.clear()
        for row in self.delivery_rows:
            endpoint = self.endpoints[row["endpoint"]]
            in_window = endpoint["from_time"] <= row["received"] < endpoint["until_time"]
            if row["state"] != "received":
                status = row["state"]  # submitted / pending：均非收件确认
            elif in_window:
                status = "confirmed"
            else:
                status = "late_receipt"
            record = {**row, "holder": endpoint["controller"], "status": status}
            self.delivery.setdefault(row["message"], []).append(record)
        return self.delivery

    def delivery_status(self, message_id: str) -> str:
        records = self.delivery.get(message_id, [])
        if not records:
            return "no_record"
        if any(r["status"] == "confirmed" for r in records):
            return "confirmed"
        if any(r["status"] == "late_receipt" for r in records):
            return "late_receipt"
        return "unconfirmed"

    def plan_handover(self, message_id: str, new_endpoint_id: str, at: int) -> dict:
        """正式交接：为允许转交的通知建立对新端的全新投递。

        只换地址改派给新承办者、或改写/合并既有投递都被拒绝；旧记录保持
        原样可追查，新投递获得独立编号。
        """
        target = self.endpoints.get(new_endpoint_id)
        if target is None:
            raise DeskError(f"新收件端不存在: {new_endpoint_id}")
        if not (target["from_time"] <= at < target["until_time"]):
            raise DeskError("交接时刻新收件端不在控制窗口内")
        if self.controls and new_endpoint_id not in self.controls:
            raise DeskError("新收件端控制身份尚未通过独立核验")
        for old in self.delivery.get(message_id, []):
            if old["endpoint"] == new_endpoint_id:
                raise DeskError("不得把已排队通知只换地址改派给新承办者")
        new_id = f"HAND-{message_id}-{new_endpoint_id}"
        record = {
            "id": new_id,
            "endpoint": new_endpoint_id,
            "message": message_id,
            "state": "submitted",
            "observed": at,
            "received": "",
            "holder": target["controller"],
            "status": "submitted",
            "handover": True,
        }
        self.delivery.setdefault(message_id, []).append(record)
        return record

    # ----------------------------------------------------------------- 核账
    def _line_status(self, line_id: str) -> LineStatus:
        line = self.lines[line_id]
        status = LineStatus(
            line=line_id,
            ticket=line["ticket"],
            member=line["member"],
            route=line["route"],
            net_cents=line["net_cents"],
        )
        for msg_id, msg in self.messages.items():
            if msg.line != line_id or msg.auth_path not in ("direct", "relay"):
                continue
            fact = {
                "kind": msg.kind,
                "revision": msg.revision,
                "source": msg_id,
                "auth_path": msg.auth_path,
                "signer": msg.keyid,
                "delegate": msg.delegate_id,
                "basis": msg.basis,
            }
            status.history.append(fact)
        status.history.sort(key=lambda f: (f["revision"], f["source"]))
        if status.history:
            status.current = status.history[-1]
            if status.current["kind"] == "reversed":
                status.reasons.append(
                    f"成员 {line['member']} 已在 revision {status.current['revision']} "
                    "冲销先前核销，按现行事实该款回到待核"
                )
        else:
            status.reasons.append(f"缺少成员 {line['member']} 对票行 {line_id} 的事实声明")

        # 投递确认是独立于成员事实的另一条办结条件：只有现行事实仍是
        # redeemed 时，投递缺口才构成待核原因；reversed 票行的缺口已由
        # 冲销原因表达，避免把两类待办混在一起。
        if status.fact_confirmed:
            sources = [f["source"] for f in status.history]
            for source in sources:
                delivery_state = self.delivery_status(source)
                status.delivery[source] = delivery_state
                if delivery_state == "late_receipt":
                    holder = next(
                        r["holder"] for r in self.delivery[source]
                        if r["status"] == "late_receipt"
                    )
                    status.reasons.append(
                        f"{source} 仅有 {holder} 的迟到回执，证明旧端曾收到该版，"
                        "当期交付仍须找原收件方查证"
                    )
                elif delivery_state in ("unconfirmed", "no_record"):
                    status.reasons.append(f"{source} 缺少落在控制窗口内的收件确认")
        return status

    def reconcile(self) -> dict:
        """生成可重复执行的核账结论。"""
        if not self.controls:
            self.verify_endpoint_controls()
        if not self.messages:
            self.ingest()
        if not self.delivery:
            self.adjudicate_delivery()

        line_statuses = {line_id: self._line_status(line_id) for line_id in sorted(self.lines)}
        tickets: dict[str, dict] = {}
        for line_id, ls in line_statuses.items():
            ticket = tickets.setdefault(
                ls.ticket,
                {"ticket": ls.ticket, "lines": [], "settled": True,
                 "net_cents": 0, "pending_cents": 0, "reasons": []},
            )
            ticket["lines"].append(asdict(ls))
            ticket["net_cents"] += ls.net_cents
            ticket["pending_cents"] += ls.pending_cents
            ticket["settled"] &= ls.settled
            ticket["reasons"].extend(f"{line_id}: {r}" for r in ls.reasons)

        open_items = {
            "missing_member_facts": [
                line_id for line_id, ls in line_statuses.items() if ls.current is None
            ],
            "reversed_lines": [
                line_id for line_id, ls in line_statuses.items()
                if ls.current and ls.current["kind"] == "reversed"
            ],
            "delivery_unconfirmed": sorted(
                msg_id for msg_id, msg in self.messages.items()
                if msg.auth_path in ("direct", "relay")
                and self.delivery_status(msg_id) in ("unconfirmed", "no_record", "late_receipt")
            ),
            "late_receipts": [
                {"message": msg_id, "records": self.delivery[msg_id]}
                for msg_id in sorted(self.delivery)
                if self.delivery_status(msg_id) == "late_receipt"
            ],
            "rejected_messages": self.rejected,
            "progress_only": sorted(
                msg_id for msg_id, m in self.messages.items() if m.auth_path == "progress"
            ),
        }
        return {
            "tickets": [tickets[name] for name in sorted(tickets)],
            "open_items": open_items,
            "totals": {
                "net_cents": sum(ls.net_cents for ls in line_statuses.values()),
                "pending_cents": sum(ls.pending_cents for ls in line_statuses.values()),
            },
        }

    # --------------------------------------------------------- 追查访问控制
    def trace_message(self, message_id: str, viewer: str) -> dict:
        """内部追查：实际签发者与授权作用域可查；成员只能查与己有关者。"""
        msg = self.messages.get(message_id)
        if msg is None:
            raise KeyError(message_id)
        related_members = {msg.member}
        if viewer != AUDITOR and viewer not in related_members:
            raise PermissionError(f"{viewer} 无权查询与己无关的联票明细")
        result = asdict(msg)
        if viewer == AUDITOR:
            result["delivery_records"] = self.delivery.get(message_id, [])
        return result

    def ticket_view(self, ticket_id: str, viewer: str) -> dict:
        report = self.reconcile()
        ticket = next((t for t in report["tickets"] if t["ticket"] == ticket_id), None)
        if ticket is None:
            raise KeyError(ticket_id)
        if viewer == AUDITOR:
            return ticket
        own_lines = {lid for lid, line in self.lines.items()
                     if line["ticket"] == ticket_id and line["member"] == viewer}
        if not own_lines:
            raise PermissionError(f"{viewer} 无权查询与己无关的联票明细")
        return {
            **ticket,
            "lines": [line for line in ticket["lines"] if line["line"] in own_lines],
        }


def main():
    desk = ReconciliationDesk()
    print(json.dumps(desk.reconcile(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
