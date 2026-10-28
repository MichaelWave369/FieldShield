"""FieldShield Sentinel tests; all IOCs and observations are synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from sentinel import load_pack, scan_files, scan_observations


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.indicators = [
            {"id": "synthetic-path", "kind": "path", "value": "artifact.txt",
             "confidence": "low", "reference": "https://example.org/research"},
            {"id": "synthetic-domain", "kind": "domain", "value": "test.example.invalid",
             "confidence": "high", "reference": "https://example.org/research"},
        ]

    def pack(self, indicators=None):
        file = self.root / "pack.json"
        file.write_text(json.dumps({
            "schema": "fieldshield.ioc-pack.v1", "source": "synthetic",
            "issued_at": "2026-01-01T00:00:00Z",
            "indicators": self.indicators if indicators is None else indicators
        }), encoding="utf-8")
        return load_pack(file)

    def test_exact_path_and_no_raw_contents(self):
        metadata, lookup = self.pack()
        folder = self.root / "device"
        folder.mkdir()
        (folder / "artifact.txt").write_text("private content")
        report = scan_files(folder, metadata, lookup)
        self.assertEqual(report["decision"], "INDICATORS_FOUND")
        self.assertEqual(report["findings"][0]["indicator_id"], "synthetic-path")
        self.assertNotIn("private content", json.dumps(report))

    def test_clean_scope_is_not_device_clearance(self):
        metadata, lookup = self.pack()
        folder = self.root / "device"
        folder.mkdir()
        (folder / "ordinary.txt").write_text("sample")
        report = scan_files(folder, metadata, lookup)
        self.assertEqual(report["decision"], "NO_MATCHES_IN_SCOPE")
        self.assertIn("not proof", report["limitations"][0])

    def test_url_domain_match_does_not_leak_query(self):
        metadata, lookup = self.pack()
        observations = self.root / "obs.json"
        observations.write_text(json.dumps({
            "schema": "fieldshield.observations.v1",
            "observations": [{"kind": "url",
                              "value": "https://test.example.invalid/private?token=supersecret"}]
        }))
        report = scan_observations(observations, metadata, lookup)
        self.assertEqual(report["decision"], "INDICATORS_FOUND")
        self.assertNotIn("supersecret", json.dumps(report))

    def test_near_match_does_not_trigger(self):
        metadata, lookup = self.pack()
        observations = self.root / "obs.json"
        observations.write_text(json.dumps({
            "schema": "fieldshield.observations.v1",
            "observations": [{"kind": "domain", "value": "nottest.example.invalid"}]
        }))
        self.assertEqual(scan_observations(observations, metadata, lookup)["decision"],
                         "NO_MATCHES_IN_SCOPE")

    def test_oversized_file_forces_incomplete(self):
        metadata, lookup = self.pack()
        folder = self.root / "device"
        folder.mkdir()
        (folder / "large.bin").write_bytes(b"abcd")
        report = scan_files(folder, metadata, lookup, max_hash_bytes=1)
        self.assertEqual(report["decision"], "INCOMPLETE")

    def test_invalid_observation_forces_incomplete_but_retains_findings(self):
        metadata, lookup = self.pack()
        observations = self.root / "obs.json"
        observations.write_text(json.dumps({
            "schema": "fieldshield.observations.v1",
            "observations": [
                {"kind": "domain", "value": "test.example.invalid"},
                {"kind": "unrecognized", "value": "x"}
            ]
        }))
        report = scan_observations(observations, metadata, lookup)
        self.assertEqual(report["decision"], "INCOMPLETE")
        self.assertEqual(len(report["findings"]), 1)

    def test_duplicate_indicator_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            self.pack([self.indicators[0], self.indicators[0]])

    def test_untrusted_text_is_not_executed(self):
        metadata, lookup = self.pack()
        folder = self.root / "device"
        folder.mkdir()
        marker = self.root / "SHOULD_NOT_EXIST"
        (folder / "example.py").write_text(
            "__import__('pathlib').Path(%r).touch()" % str(marker))
        scan_files(folder, metadata, lookup)
        self.assertFalse(marker.exists())

    def test_symlink_target_rejected(self):
        metadata, lookup = self.pack()
        file = self.root / "content"
        file.write_text("x")
        link = self.root / "link"
        try:
            link.symlink_to(file)
        except (OSError, NotImplementedError):
            self.skipTest("No symlink support")
        with self.assertRaises(ValueError):
            scan_files(link, metadata, lookup)


if __name__ == "__main__":
    unittest.main()
