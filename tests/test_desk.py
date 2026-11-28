"""核账台身份、授权、交接与结清规则测试。"""
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from desk import AUDITOR, DeskError, ReconciliationDesk
from wireverify import WireError, content_digest, reconstruct_signature_base

ROOT = Path(__file__).resolve().parents[1]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sign_http(key: Ed25519PrivateKey, keyid: str, body: dict, message_id: str, created=1795741500):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = {
        "content-digest": content_digest(raw),
        "notification-id": message_id,
        "signature-input": (
            f"sig1=(\"@method\" \"@target-uri\" \"content-digest\" \"notification-id\");"
            f"created={created};keyid=\"{keyid}\";alg=\"ed25519\""
        ),
    }
    request = {
        "id": message_id,
        "method": "POST",
        "target_uri": "https://ledger.example.invalid/v1/notifications",
        "body": _b64(raw),
        "headers": headers,
    }
    headers["signature"] = "sig1=:" + _b64(key.sign(reconstruct_signature_base(request))) + ":"
    return request


class DeskFixtureTests(unittest.TestCase):
    def setUp(self):
        self.desk = ReconciliationDesk()
        self.desk.verify_endpoint_controls()
        self.desk.ingest()
        self.desk.adjudicate_delivery()
        self.report = self.desk.reconcile()

    def test_message_identities_are_classified(self):
        messages = self.desk.messages
        self.assertEqual(messages["msg-a"].auth_path, "direct")
        self.assertEqual(messages["msg-a"].member, "M-A")
        self.assertEqual(messages["msg-ar"].auth_path, "relay")
        self.assertEqual(messages["msg-ar"].member, "M-A")
        self.assertEqual(messages["msg-ar"].delegate_id, "DE-1")
        self.assertEqual(messages["msg-ap"].auth_path, "progress")
        self.assertEqual(messages["msg-ap"].delegate_id, "DE-2")
        self.assertEqual(messages["msg-b2"].kind, "reversed")
        self.assertEqual(self.desk.rejected, [])

    def test_relay_keeps_two_distinct_identities(self):
        relayed = self.desk.messages["msg-ar"]
        # 外层 HTTP 签名是合办机构，内层成员身份单独保留在事实来源里。
        self.assertEqual(relayed.keyid, "partner")
        line = next(l for t in self.report["tickets"] for l in t["lines"] if l["line"] == "L-1")
        inner = next(f for f in line["history"] if f["source"] == "msg-ar")
        self.assertEqual(inner["auth_path"], "relay")
        self.assertEqual(inner["delegate"], "DE-1")

    def test_progress_notice_creates_no_member_fact(self):
        for ticket in self.report["tickets"]:
            for line in ticket["lines"]:
                self.assertNotIn("msg-ap", [f["source"] for f in line["history"]])
        self.assertIn("msg-ap", self.report["open_items"]["progress_only"])

    def test_latest_revision_wins_and_superseded_basis_is_retained(self):
        line = next(l for t in self.report["tickets"] for l in t["lines"] if l["line"] == "L-2")
        self.assertEqual(line["current"]["kind"], "reversed")
        self.assertEqual(line["current"]["revision"], 2)
        self.assertEqual([f["revision"] for f in line["history"]], [1, 2])
        self.assertTrue(any("冲销" in r for r in line["reasons"]))

    def test_same_url_two_holders_are_separate_identities(self):
        self.assertEqual(self.desk.endpoints["END-1"]["url"], self.desk.endpoints["END-2"]["url"])
        self.assertNotEqual(
            self.desk.endpoints["END-1"]["controller"],
            self.desk.endpoints["END-2"]["controller"],
        )
        self.assertEqual(self.desk.controls["END-1"]["keyid"], "host-a")
        self.assertEqual(self.desk.controls["END-2"]["keyid"], "host-new")

    def test_msg_a_receipt_is_late_and_never_merged(self):
        records = self.desk.delivery["msg-a"]
        self.assertEqual([r["status"] for r in records],
                         ["submitted", "pending", "late_receipt"])
        self.assertEqual(self.desk.delivery_status("msg-a"), "late_receipt")
        # 三次观测各自保留，没有合并成一条。
        self.assertEqual(len({r["id"] for r in records}), 3)

    def test_no_ticket_settles_and_pending_is_itemized(self):
        self.assertFalse(any(t["settled"] for t in self.report["tickets"]))
        self.assertEqual(self.report["totals"]["pending_cents"], 6300)
        self.assertEqual(self.report["open_items"]["missing_member_facts"], ["L-3"])
        self.assertEqual(self.report["open_items"]["reversed_lines"], ["L-2"])

    def test_repeated_runs_are_deterministic(self):
        again = ReconciliationDesk().reconcile()
        self.assertEqual(json.dumps(again, sort_keys=True),
                         json.dumps(self.report, sort_keys=True))

    def test_handover_creates_fresh_delivery_but_refuses_reroute_in_place(self):
        fresh = self.desk.plan_handover("msg-a", "END-2", at=600)
        self.assertTrue(fresh["handover"])
        self.assertNotIn(fresh["id"], {r["id"] for r in self.desk.delivery["msg-a"]
                                       if not r.get("handover")})
        with self.assertRaises(DeskError):
            self.desk.plan_handover("msg-a", "END-2", at=601)
        with self.assertRaises(DeskError):
            self.desk.plan_handover("msg-a", "END-1", at=520)

    def test_access_control_for_traces_and_ticket_views(self):
        self.assertEqual(self.desk.trace_message("msg-b", AUDITOR)["member"], "M-B")
        self.assertEqual(self.desk.trace_message("msg-b", "M-B")["message_id"], "msg-b")
        with self.assertRaises(PermissionError):
            self.desk.trace_message("msg-b", "M-A")
        with self.assertRaises(PermissionError):
            self.desk.ticket_view("bundle-22", "M-A")
        view = self.desk.ticket_view("bundle-21", "M-B")
        self.assertEqual({l["line"] for l in view["lines"]}, {"L-2"})


class DeskSyntheticTests(unittest.TestCase):
    """用临时密钥构造越权与篡改情形，不改动资料目录。"""

    def setUp(self):
        self.desk = ReconciliationDesk()
        self.desk.verify_endpoint_controls()
        self.member_a = Ed25519PrivateKey.generate()
        self.member_b = Ed25519PrivateKey.generate()
        self.partner = Ed25519PrivateKey.generate()
        self.desk.public_keys["member-a"] = load_pem_public_key(
            self.member_a.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.desk.public_keys["member-b"] = load_pem_public_key(
            self.member_b.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.desk.public_keys["partner"] = load_pem_public_key(
            self.partner.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    def _reload(self, requests):
        self.desk.requests = requests
        self.desk.messages = {}
        self.desk.rejected = []
        return self.desk.ingest()

    def test_member_cannot_claim_route_outside_registration(self):
        body = {"kind": "redeemed", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-2"}
        self._reload([_sign_http(self.member_a, "member-a", body, "x-1")])
        self.assertEqual(self.desk.messages["x-1"].auth_path, "rejected")
        self.assertIn("R-2", self.desk.rejected[0]["reason"])

    def test_member_fact_must_bind_to_its_own_line(self):
        body = {"kind": "redeemed", "line": "L-2", "member": "M-A", "revision": 1, "route": "R-1"}
        self._reload([_sign_http(self.member_a, "member-a", body, "x-2")])
        self.assertEqual(self.desk.messages["x-2"].auth_path, "rejected")
        self.assertIn("不绑定", self.desk.rejected[0]["reason"])

    def test_unregistered_signer_cannot_speak_for_member(self):
        stranger = Ed25519PrivateKey.generate()
        self.desk.public_keys["stranger"] = load_pem_public_key(
            stranger.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        body = {"kind": "redeemed", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-1"}
        self._reload([_sign_http(stranger, "stranger", body, "x-3")])
        self.assertEqual(self.desk.rejected[0]["message"], "x-3")

    def test_partner_self_declared_member_fact_is_refused(self):
        body = {"kind": "redeemed", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-1"}
        self._reload([_sign_http(self.partner, "partner", body, "x-4")])
        self.assertEqual(self.desk.messages["x-4"].auth_path, "rejected")
        self.assertIn("不得", self.desk.rejected[0]["reason"])

    def test_progress_notice_declaring_redemption_is_refused(self):
        body = {"kind": "progress", "line": "L-1", "member": "M-A", "revision": 1,
                "route": "R-1", "declares": "redeemed"}
        self._reload([_sign_http(self.partner, "partner", body, "x-5")])
        self.assertEqual(self.desk.messages["x-5"].auth_path, "rejected")

    def test_partner_without_relay_grant_cannot_relay(self):
        # 把合办机构的 relay 授权临时撤掉，只保留 progress。
        self.desk.delegates = [d for d in self.desk.delegates if d["grant"] != "relay"]
        inner_bytes = json.dumps(
            {"kind": "redeemed", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-1"},
            separators=(",", ":")).encode()
        inner = {
            "keyid": "member-a",
            "signature": _b64(self.member_a.sign(inner_bytes)),
            "signed_bytes": _b64(inner_bytes),
        }
        self._reload([_sign_http(self.partner, "partner", {"forwarded": inner}, "x-6")])
        self.assertEqual(self.desk.messages["x-6"].auth_path, "rejected")
        self.assertIn("relay", self.desk.rejected[0]["reason"])

    def test_relay_with_tampered_inner_signature_is_rejected(self):
        inner_bytes = json.dumps(
            {"kind": "redeemed", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-1"},
            separators=(",", ":")).encode()
        inner = {
            "keyid": "member-a",
            "signature": _b64(self.member_b.sign(inner_bytes)),  # 用他人密钥签内层
            "signed_bytes": _b64(inner_bytes),
        }
        self._reload([_sign_http(self.partner, "partner", {"forwarded": inner}, "x-7")])
        self.assertEqual(self.desk.messages["x-7"].auth_path, "rejected")
        self.assertIsInstance(self.desk.rejected[0]["reason"], str)

    def test_tampered_outer_http_signature_is_rejected(self):
        body = {"kind": "progress", "line": "L-1", "member": "M-A", "revision": 1, "route": "R-1"}
        request = _sign_http(self.partner, "partner", body, "x-8")
        request["headers"]["notification-id"] = "changed-after-signing"
        self._reload([request])
        self.assertEqual(self.desk.messages["x-8"].auth_path, "rejected")

    def test_control_claim_with_wrong_key_is_rejected(self):
        desk = ReconciliationDesk()
        rogue = Ed25519PrivateKey.generate()
        desk.public_keys["host-a"] = load_pem_public_key(
            rogue.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(WireError):
            desk.verify_endpoint_controls()


if __name__ == "__main__":
    unittest.main()
