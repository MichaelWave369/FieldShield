"""Golden cross-runtime URL authority profile tests, synthetic only."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sentinel import _normalize, _safe_url_hostname, load_pack_bytes, scan_observations

CORPUS = Path(__file__).resolve().parent / "fixtures" / "fieldshield-url-authority-parity.v1.json"


class URLAuthorityParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        if cls.corpus["schema"] != "fieldshield.phios.url-authority-parity.v1":
            raise AssertionError("Unsupported URL authority parity contract")

    def test_accepted_authorities_have_stable_hostnames(self):
        self.assertEqual(len(self.corpus["accepted"]), 9)
        for case in self.corpus["accepted"]:
            with self.subTest(case=case["value"]):
                self.assertEqual(_normalize("url", case["value"]), case["value"])
                self.assertEqual(_safe_url_hostname(case["value"]), case["hostname"])

    def test_ambiguous_authorities_fail_closed(self):
        self.assertEqual(len(self.corpus["rejected"]), 18)
        for case in self.corpus["rejected"]:
            with self.subTest(case=case["why"]):
                with self.assertRaises(ValueError):
                    _normalize("url", case["value"])

    def test_ambiguous_observation_marks_incomplete_without_match(self):
        pack = {
            "schema": "fieldshield.ioc-pack.v1",
            "source": "synthetic URL profile regression only",
            "issued_at": "2026-01-01T00:00:00Z",
            "indicators": [{
                "id": "valid-host", "kind": "domain",
                "value": "example.invalid", "confidence": "low",
                "reference": "https://www.rfc-editor.org/rfc/rfc2606",
            }],
        }
        metadata, lookup = load_pack_bytes(json.dumps(pack).encode())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps({
                "schema": "fieldshield.observations.v1",
                "observations": [
                    {"kind": "url", "value": "https://ex%61mple.invalid/private"},
                    {"kind": "domain", "value": "unrelated.example.invalid"},
                ],
            }), encoding="utf-8")
            report = scan_observations(path, metadata, lookup)
        self.assertEqual(report["counts"]["inspected"], 1)
        self.assertEqual(report["counts"]["uninspected"], 1)
        self.assertEqual(report["counts"]["findings"], 0)
        self.assertEqual(report["decision"], "INCOMPLETE")
        self.assertNotIn("ex%61mple", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
