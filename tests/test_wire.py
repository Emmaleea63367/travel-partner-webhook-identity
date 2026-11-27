"""核对线路运营方协议样本的实际签名。"""
from base64 import b64decode, b64encode
import hashlib
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.serialization import load_pem_public_key


WIRE = Path(__file__).resolve().parents[1] / "wire"


class MessageWireTests(unittest.TestCase):
    def test_captured_request_body_and_signature(self):
        request = json.loads((WIRE / "requests.json").read_text())[0]
        header = request["headers"]
        digest = b64encode(hashlib.sha256(b64decode(request["body"])).digest()).decode()
        self.assertEqual(header["content-digest"], "sha-256=:" + digest + ":")
        encoded_sig = header["signature"].removeprefix("sig1=:").removesuffix(":")
        key = load_pem_public_key((WIRE / "member-a.pub").read_bytes())
        key.verify(b64decode(encoded_sig), (WIRE / "wire-capture.txt").read_bytes())
