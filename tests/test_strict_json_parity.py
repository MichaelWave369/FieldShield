"""Cross-runtime strict UTF-8 JSON ambiguity contract (synthetic inputs only)."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sentinel import _strict_json, load_pack_bytes, scan_observations
from sentinel_verified import _json as verified_json

CONTRACT = (Path(__file__).resolve().parent / "fixtures" /
            "fieldshield-strict-json-parity.v1.json")


class StrictJSONParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CONTRACT.read_text(encoding="utf-8"))
        assert cls.corpus["schema"] == "fieldshield.phios.strict-json-parity.v1"

    def test_goldens_accepted_by_python_and_verified_manifest_reader(self):
        self.assertEqual(len(self.corpus["accepted"]), 6)
        for vector in self.corpus["accepted"]:
            with self.subTest(accepted=vector["id"]):
                raw = vector["raw"].encode("utf-8")
                result = _strict_json(raw, "Synthetic parity")
                self.assertIsInstance(result, dict)
                self.assertEqual(result, verified_json(raw, "Synthetic parity"))

    def test_goldens_rejected_by_python_and_verified_manifest_reader(self):
        self.assertEqual(len(self.corpus["rejected"]), 23)
        for vector in self.corpus["rejected"]:
            with self.subTest(rejected=vector["id"]):
                raw = vector["raw"].encode("utf-8")
                with self.assertRaises(ValueError):
                    _strict_json(raw, "Synthetic parity")
                with self.assertRaises(ValueError):
                    verified_json(raw, "Synthetic parity")

    def test_real_pack_gate_rejects_hidden_duplicate_indicator_field(self):
        raw = (b'{"schema":"fieldshield.ioc-pack.v1","source":"synthetic",'
               b'"issued_at":"2026-01-01T00:00:00Z","indicators":['
               b'{"id":"legit","id":"shadow","kind":"domain",'
               b'"value":"demo.example.invalid","confidence":"low",'
               b'"reference":"https://www.rfc-editor.org/rfc/rfc2606"}]}')
        with self.assertRaises(ValueError):
            load_pack_bytes(raw)

    def test_real_observations_gate_rejects_duplicate_data(self):
        pack = {
            "schema": "fieldshield.ioc-pack.v1",
            "source": "synthetic", "issued_at": "2026-01-01T00:00:00Z",
            "indicators": [{"id": "sample", "kind": "domain",
                            "value": "demo.example.invalid",
                            "confidence": "low",
                            "reference": "https://www.rfc-editor.org/rfc/rfc2606"}],
        }
        metadata, lookup = load_pack_bytes(json.dumps(pack).encode("utf-8"))
        raw = ('{"schema":"fieldshield.observations.v1",'
               '"observations":[{"kind":"domain","value":"demo.example.invalid",'
               '"value":"not-demo.example.invalid"}]}')
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "observations.json"
            evidence.write_text(raw, encoding="utf-8")
            with self.assertRaises(ValueError):
                scan_observations(evidence, metadata, lookup)

    def test_invalid_utf8_and_nonfinite_values_fail(self):
        with self.assertRaises(ValueError):
            _strict_json(b'{"a":"\xff"}')
        with self.assertRaises(ValueError):
            _strict_json(b'{"n":1e99999}')
        with self.assertRaises(ValueError):
            _strict_json(b'{"n":9007199254740992}')


if __name__ == "__main__":
    unittest.main()
