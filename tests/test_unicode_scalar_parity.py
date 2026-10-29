"""Reject lone surrogate escapes in all security JSON ingress paths.

The fixture is byte-identical to PhiOS's WebCrypto browser test corpus.
All data is synthetic, without real private evidence or signers.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sentinel import _strict_json, load_pack_bytes, scan_observations
from sentinel_verified import _json as verified_json

FIXTURE = Path(__file__).resolve().parent / "fixtures/fieldshield-unicode-scalar-parity.v1.json"


class UnicodeScalarParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert cls.corpus["schema"] == "fieldshield.phios.unicode-scalar-parity.v1"

    def test_valid_unicode_surrogate_pairs_remain_accepted(self):
        self.assertEqual(len(self.corpus["accepted"]), 7)
        for case in self.corpus["accepted"]:
            with self.subTest(case=case["id"]):
                data = case["raw"].encode("utf-8")
                assert _strict_json(data) == verified_json(data, "synthetic")

    def test_unpaired_unicode_surrogates_fail_closed_for_all_security_readers(self):
        self.assertEqual(len(self.corpus["rejected"]), 12)
        for case in self.corpus["rejected"]:
            with self.subTest(case=case["id"]):
                data = case["raw"].encode("utf-8")
                with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
                    _strict_json(data)
                with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
                    verified_json(data, "synthetic")

    def test_malformed_surrogate_inside_signed_pack_provenance_rejected(self):
        pack = (b'{"schema":"fieldshield.ioc-pack.v1",'
                b'"source":"\\ud800","issued_at":"2026-01-01T00:00:00Z",'
                b'"indicators":[{"id":"demo","kind":"domain",'
                b'"value":"demo.example.invalid","confidence":"low",'
                b'"reference":"https://www.rfc-editor.org/rfc/rfc2606"}]}')
        with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
            load_pack_bytes(pack)

    def test_malformed_surrogate_inside_observations_rejected(self):
        pack = {
            "schema": "fieldshield.ioc-pack.v1",
            "source": "synthetic",
            "issued_at": "2026-01-01T00:00:00Z",
            "indicators": [{
                "id": "demo", "kind": "domain",
                "value": "demo.example.invalid", "confidence": "low",
                "reference": "https://www.rfc-editor.org/rfc/rfc2606",
            }],
        }
        metadata, lookup = load_pack_bytes(json.dumps(pack).encode())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "observations.json"
            path.write_text(
                '{"schema":"fieldshield.observations.v1",'
                '"observations":[{"kind":"process","value":"\\ud800"}]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
                scan_observations(path, metadata, lookup)


if __name__ == "__main__":
    unittest.main()
