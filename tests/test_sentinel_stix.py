"""STIX importer contract tests. Fixtures are fabricated and entirely harmless."""
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from sentinel import load_pack, scan_observations
from sentinel_stix import convert_bundle, main, read_bundle

NOW = datetime(2026, 10, 28, 16, 0, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
REF = "https://www.rfc-editor.org/rfc/rfc2606"
ID_A = "indicator--11111111-1111-4111-8111-111111111111"
ID_B = "indicator--22222222-2222-4222-8222-222222222222"


def indicator(pattern, *, ident=ID_A, **kwargs):
    result = {"type": "indicator", "spec_version": "2.1",
              "id": ident, "pattern_type": "stix", "pattern_version": "2.1",
              "pattern": pattern, "valid_from": "2026-01-01T00:00:00Z"}
    result.update(kwargs)
    return result


def bundle(*objects):
    return {"type": "bundle",
            "id": "bundle--33333333-3333-4333-8333-333333333333",
            "objects": list(objects)}


def convert(value):
    return convert_bundle(value, source_name="Synthetic research", reference_url=REF,
                          bundle_sha256=DIGEST, now=NOW)


class StixImporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_domain_converts_into_existing_sentinel(self):
        pack = convert(bundle(indicator("[domain-name:value = 'test.example.invalid']", confidence=85)))
        self.assertEqual(pack["indicators"][0]["kind"], "domain")
        self.assertEqual(pack["indicators"][0]["confidence"], "high")
        self.assertEqual(pack["origin_stix"]["bundle_sha256"], DIGEST)
        # The STIX conversion above uses a frozen future-capable clock. Make
        # this separate loader integration fixture historically issued so its
        # result never depends on the GitHub runner's wall-clock minute.
        pack["issued_at"] = "2026-01-02T00:00:00+00:00"
        pack_path = self.root / "pack.json"
        pack_path.write_text(json.dumps(pack), encoding="utf-8")
        metadata, lookup = load_pack(pack_path)
        obs_path = self.root / "observations.json"
        obs_path.write_text(json.dumps({
            "schema": "fieldshield.observations.v1",
            "observations": [{"kind": "domain", "value": "test.example.invalid"}]
        }), encoding="utf-8")
        report = scan_observations(obs_path, metadata, lookup)
        self.assertEqual(report["decision"], "INDICATORS_FOUND")
        self.assertEqual(report["findings"][0]["indicator_id"], ID_A)

    def test_future_issued_pack_is_rejected_by_live_loader(self):
        pack = convert(bundle(indicator("[domain-name:value = 'test.example.invalid']")))
        # Use a relative future timestamp so this guard is tested regardless
        # of which day or minute the CI runner executes.
        pack["issued_at"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        pack_path = self.root / "future-pack.json"
        pack_path.write_text(json.dumps(pack), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "issued_at is in the future"):
            load_pack(pack_path)

    def test_file_hash_and_app_id_supported(self):
        sha = "f" * 64
        pack = convert(bundle(
            indicator("[file:hashes.'SHA-256' = '" + sha + "']", ident=ID_A),
            indicator("[app:id = 'org.example.demo']", ident=ID_B)
        ))
        self.assertEqual({(x["kind"], x["value"]) for x in pack["indicators"]},
                         {("sha256", sha), ("bundle_id", "org.example.demo")})

    def test_complex_or_pattern_refused_whole_bundle(self):
        mixed = bundle(
            indicator("[domain-name:value = 'safe.example.invalid']", ident=ID_A),
            indicator("[domain-name:value = 'a.example.invalid' OR domain-name:value = 'b.example.invalid']", ident=ID_B)
        )
        with self.assertRaisesRegex(ValueError, "Refusing partial import"):
            convert(mixed)

    def test_and_and_temporal_qualifier_refused(self):
        for pattern in (
            "[domain-name:value = 'a.example.invalid' AND url:value = 'https://example.invalid']",
            "[domain-name:value = 'a.example.invalid'] REPEATS 5 TIMES",
            "[domain-name:value = 'a.example.invalid'] FOLLOWEDBY [domain-name:value = 'b.example.invalid']",
            "[domain-name:value = 'a\\\\b.example.invalid']",
            "[file:name = 'payload.exe']",
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "Refusing partial import"):
                    convert(bundle(indicator(pattern)))

    def test_validity_and_revocation_not_loaded(self):
        pack = convert(bundle(
            indicator("[domain-name:value = 'active.example.invalid']", ident=ID_A),
            indicator("[domain-name:value = 'expired.example.invalid']", ident=ID_B,
                      valid_until="2026-04-01T00:00:00Z"),
            indicator("[domain-name:value = 'revoked.example.invalid']",
                      ident="indicator--44444444-4444-4444-8444-444444444444",
                      revoked=True),
            indicator("[domain-name:value = 'future.example.invalid']",
                      ident="indicator--55555555-5555-4555-8555-555555555555",
                      valid_from="2027-01-01T00:00:00Z"),
            {"type": "identity", "id": "identity--66666666-6666-4666-8666-666666666666"}
        ))
        self.assertEqual(len(pack["indicators"]), 1)
        self.assertEqual(pack["origin_stix"]["counts_not_imported"],
                         {"revoked": 1, "expired": 1, "not_yet_active": 1, "non_indicator_objects": 1})

    def test_future_only_is_not_silent_empty_pack(self):
        future = indicator("[domain-name:value = 'future.example.invalid']",
                           valid_from="2027-01-01T00:00:00Z")
        with self.assertRaisesRegex(ValueError, "No supported currently valid"):
            convert(bundle(future))

    def test_duplicate_indicator_id_refused(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            convert(bundle(
                indicator("[domain-name:value = 'a.example.invalid']"),
                indicator("[domain-name:value = 'b.example.invalid']")
            ))

    def test_stix20_refused(self):
        item = indicator("[domain-name:value = 'test.example.invalid']")
        item["spec_version"] = "2.0"
        with self.assertRaisesRegex(ValueError, "Refusing partial import"):
            convert(bundle(item))

    def test_invalid_url_and_confidence_refused(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            convert_bundle(bundle(indicator("[domain-name:value = 'test.example.invalid']")),
                           source_name="test", reference_url="http://insecure.invalid",
                           bundle_sha256=DIGEST, now=NOW)
        with self.assertRaisesRegex(ValueError, "Refusing partial import"):
            convert(bundle(indicator("[domain-name:value = 'test.example.invalid']", confidence=True)))

    def test_unsupported_escape_and_nonexistent_path_refused(self):
        with self.assertRaisesRegex(ValueError, "Refusing partial import"):
            convert(bundle(indicator("[url:value = 'https://a.example.invalid/a\\'b']")))
        with self.assertRaises(ValueError):
            read_bundle(self.root / "does-not-exist.json")

    def test_cli_no_implicit_output_and_explicit_create(self):
        file = self.root / "bundle.stix2"
        file.write_text(json.dumps(bundle(indicator("[domain-name:value = 'test.example.invalid']"))),
                        encoding="utf-8")
        pack_path = self.root / "output.json"
        args = [str(file), "--source", "Synthetic",
                "--reference", REF, "--output", str(pack_path)]
        self.assertEqual(main(args), 0)
        self.assertTrue(pack_path.is_file())
        self.assertEqual(main(args), 2)  # Refuses to overwrite.
        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_no_script_execution_from_pattern(self):
        marker = self.root / "SHOULD_NOT_EXIST"
        payload = "__import__('pathlib').Path(%r).touch()" % str(marker)
        with self.assertRaisesRegex(ValueError, "Refusing partial import"):
            convert(bundle(indicator("[domain-name:value = '" + payload + "']")))
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
