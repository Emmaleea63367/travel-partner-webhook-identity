"""RFC 9421 / RFC 9530 子集的签名与摘要核验测试。"""
import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from wireverify import WireError, content_digest, reconstruct_signature_base, verify_request, verify_signed_bytes

WIRE = Path(__file__).resolve().parents[1] / "wire"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sign_request(key: Ed25519PrivateKey, keyid: str, body: dict, created: int = 1795741500,
                 components=("@method", "@target-uri", "content-digest", "notification-id")):
    """测试用签名端：按约定子集构造一条完整请求。"""
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = {"content-digest": content_digest(raw), "notification-id": "n-1"}
    comp_rendered = " ".join(f'"{c}"' for c in components)
    headers["signature-input"] = (
        f"sig1=({comp_rendered});created={created};keyid=\"{keyid}\";alg=\"ed25519\""
    )
    request = {
        "id": "n-1",
        "method": "POST",
        "target_uri": "https://ledger.example.invalid/v1/notifications",
        "body": _b64(raw),
        "headers": headers,
    }
    base = reconstruct_signature_base(request)
    headers["signature"] = "sig1=:" + _b64(key.sign(base)) + ":"
    return request


class WireVerifyTests(unittest.TestCase):
    def setUp(self):
        self.keys = {
            p.stem: load_pem_public_key(p.read_bytes()) for p in WIRE.glob("*.pub")
        }
        self.requests = json.loads((WIRE / "requests.json").read_text())

    def test_every_captured_request_verifies(self):
        for request in self.requests:
            with self.subTest(message=request["id"]):
                info = verify_request(request, self.keys)
                self.assertEqual(info.alg, "ed25519")
                self.assertTrue(info.covers_required_subset())

    def test_captured_signature_base_matches_retained_sample(self):
        request = self.requests[0]
        self.assertEqual(
            reconstruct_signature_base(request),
            (WIRE / "wire-capture.txt").read_bytes(),
        )

    def test_forwarded_inner_and_receive_control_verify_on_raw_bytes(self):
        forwarded = json.loads(base64.b64decode(self.requests[4]["body"]))["forwarded"]
        claim = verify_signed_bytes(forwarded, self.keys)
        self.assertEqual(claim["member"], "M-A")
        self.assertEqual(claim["kind"], "redeemed")
        for material in json.loads((WIRE / "receive-control.json").read_text()):
            control = verify_signed_bytes(material, self.keys)
            self.assertIn(control["binding"], ("END-1", "END-2"))

    def test_tampered_body_fails_digest_before_signature(self):
        request = json.loads(json.dumps(self.requests[0]))
        body = json.loads(base64.b64decode(request["body"]))
        body["revision"] = 9
        request["body"] = _b64(json.dumps(body, separators=(",", ":")).encode())
        with self.assertRaises(WireError):
            verify_request(request, self.keys)

    def test_signature_from_other_key_is_rejected(self):
        request = json.loads(json.dumps(self.requests[0]))
        stranger = Ed25519PrivateKey.generate()
        request["headers"]["signature"] = "sig1=:" + _b64(
            stranger.sign(reconstruct_signature_base(request))
        ) + ":"
        with self.assertRaises(WireError):
            verify_request(request, self.keys)

    def test_unregistered_keyid_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        request = sign_request(key, "unknown-member", {"kind": "redeemed"})
        with self.assertRaises(WireError):
            verify_request(request, self.keys)

    def test_signature_must_cover_target_body_and_delivery(self):
        key = Ed25519PrivateKey.generate()
        request = sign_request(
            key, "member-a",
            components=("@method", "@target-uri"),
            body={"kind": "redeemed"},
        )
        with self.assertRaises(WireError):
            verify_request(request, self.keys)

    def test_alg_is_pinned_to_ed25519(self):
        key = Ed25519PrivateKey.generate()
        request = sign_request(key, "member-a", {"kind": "redeemed"})
        request["headers"]["signature-input"] = request["headers"][
            "signature-input"
        ].replace("alg=\"ed25519\"", "alg=\"hmac-sha256\"")
        with self.assertRaises(WireError):
            verify_request(request, self.keys)

    def test_roundtrip_sign_and_verify(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        request = sign_request(key, "test", {"kind": "redeemed", "line": "L-9"})
        # 公钥可直接以 PEM/字节对象提供。
        info = verify_request(request, {"test": load_pem_public_key(
            key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )})
        self.assertEqual(info.keyid, "test")
        self.assertIsInstance(pub, bytes)

    def test_inner_material_rejects_wrong_signature(self):
        forwarded = json.loads(base64.b64decode(self.requests[4]["body"]))["forwarded"]
        forwarded["signature"] = _b64(Ed25519PrivateKey.generate().sign(b"x"))
        with self.assertRaises(WireError):
            verify_signed_bytes(forwarded, self.keys)

    def test_digest_uses_rfc9530_sha256(self):
        raw = base64.b64decode(self.requests[0]["body"])
        expected = "sha-256=:" + _b64(hashlib.sha256(raw).digest()) + ":"
        self.assertEqual(content_digest(raw), expected)


if __name__ == "__main__":
    unittest.main()
