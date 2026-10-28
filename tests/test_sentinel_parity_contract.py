"""Cross-runtime golden contract vectors for FieldShield Sentinel/PhiOS.

The fixture is duplicated byte-for-byte in PhiOS's browser test tree and must
be updated in both repos together. All indicators are synthetic.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sentinel import load_pack_bytes, scan_observations


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "fieldshield-observation-parity.v1.json"


class ObservationParityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(FIXTURE.read_text(encoding="utf-8"))
        if cls.contract.get("schema") != "fieldshield.phios.observations-parity.v1":
            raise AssertionError("Unknown parity contract schema")
        # The same serialized content is used by the runtime and test.
        pack_bytes = json.dumps(cls.contract["pack"], separators=(",", ":")).encode("utf-8")
        cls.metadata, cls.lookup = load_pack_bytes(pack_bytes)

    def test_golden_vectors_match_python_sentinel(self):
        self.assertEqual(len(self.contract["cases"]), 7)
        for scenario in self.contract["cases"]:
            with self.subTest(case=scenario["id"]):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "observations.json"
                    path.write_text(json.dumps({
                        "schema": "fieldshield.observations.v1",
                        "observations": scenario["observations"],
                    }), encoding="utf-8")
                    report = scan_observations(path, self.metadata, self.lookup)
                actual = {
                    "decision": report["decision"],
                    "inspected": report["counts"]["inspected"],
                    "uninspected": report["counts"]["uninspected"],
                    "findings": [
                        {
                            "indicatorId": match["indicator_id"],
                            "kind": match["kind"],
                            "observationIndex": match["location"]["index"],
                        } for match in report["findings"]
                    ],
                }
                self.assertEqual(actual, scenario["expected"])
                self.assertFalse(report["network_access"])
                self.assertFalse(report["wrote_files"])

    def test_raw_observation_secrets_are_not_in_python_report(self):
        scenario = next(x for x in self.contract["cases"]
                        if x["id"] == "url-hostname-exact-fallback-without-raw-value")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.json"
            path.write_text(json.dumps({
                "schema": "fieldshield.observations.v1",
                "observations": scenario["observations"],
            }), encoding="utf-8")
            report = scan_observations(path, self.metadata, self.lookup)
        self.assertNotIn("only-in-evidence", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
