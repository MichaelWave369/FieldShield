"""Sentinel v0.3 verified-pack tests; no private keys are stored in the repo."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel import scan_observations, load_pack_bytes
from sentinel_verified import (
    TRUST_SCHEMA, read_snapshot, sign_bytes, verify_bytes, main,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def json_bytes(item):
    return json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8")


class VerifiedPacksTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = Ed25519PrivateKey.generate()
        self.private_pem = self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        self.pub_raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.pack = json_bytes({
            "schema": "fieldshield.ioc-pack.v1",
            "source": "Synthetic test only (not real spyware intelligence)",
            "issued_at": "2026-01-01T00:00:00Z",
            "indicators": [{
                "id": "synthetic-1", "kind": "domain",
                "value": "spyware-demo.example.invalid",
                "confidence": "low",
                "reference": "https://www.rfc-editor.org/rfc/rfc2606",
            }]
        })
        self.manifest = sign_bytes(self.pack, self.private_pem,
                                   publisher="example-publisher", key_id="key-1",
                                   issued_at="2026-02-01T00:00:00Z",
                                   expires_at="2027-01-01T00:00:00Z", now=NOW)
        self.trust = {
            "schema": TRUST_SCHEMA,
            "publishers": [{
                "id": "example-publisher",
                "keys": [{"id": "key-1", "algorithm": "ed25519", "state": "trusted",
                          "public_key_b64": base64.b64encode(self.pub_raw).decode("ascii")}],
                "blocked_pack_sha256": [],
                "minimum_issued_at": "2026-01-01T00:00:00Z",
            }],
        }

    def verify(self, *, pack=None, manifest=None, trust=None, now=NOW):
        return verify_bytes(self.pack if pack is None else pack,
                            json_bytes(self.manifest if manifest is None else manifest),
                            json_bytes(self.trust if trust is None else trust), now=now)

    def test_valid_signature_loads_same_bytes(self):
        metadata, lookup = self.verify()
        self.assertEqual(metadata["pack_sha256"], hashlib.sha256(self.pack).hexdigest())
        self.assertEqual(metadata["verification"]["status"], "ed25519-verified")
        self.assertEqual(metadata["verification"]["publisher"], "example-publisher")
        self.assertIn(("domain", "spyware-demo.example.invalid"), lookup)

    def test_verified_scan_works_with_synthetic_observations(self):
        metadata, lookup = self.verify()
        path = self.root / "observations.json"
        path.write_bytes(json_bytes({
            "schema": "fieldshield.observations.v1",
            "observations": [{"kind": "domain", "value": "spyware-demo.example.invalid"}]
        }))
        report = scan_observations(path, metadata, lookup)
        self.assertEqual(report["decision"], "INDICATORS_FOUND")
        self.assertEqual(report["indicator_pack"]["verification"]["status"], "ed25519-verified")

    def test_tampered_pack_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.verify(pack=self.pack + b" ")

    def test_tampered_signature_is_rejected(self):
        manifest = dict(self.manifest)
        sig = bytearray(base64.b64decode(manifest["signature_b64"]))
        sig[0] ^= 1
        manifest["signature_b64"] = base64.b64encode(bytes(sig)).decode("ascii")
        with self.assertRaisesRegex(ValueError, "signature invalid"):
            self.verify(manifest=manifest)

    def test_relabeling_publisher_breaks_signature(self):
        trust = json.loads(json.dumps(self.trust))
        trust["publishers"][0]["id"] = "impostor"
        manifest = dict(self.manifest, publisher="impostor")
        with self.assertRaisesRegex(ValueError, "signature invalid"):
            self.verify(trust=trust, manifest=manifest)

    def test_unknown_publisher_rejected(self):
        trust = {"schema": TRUST_SCHEMA, "publishers": []}
        with self.assertRaisesRegex(ValueError, "Unknown publisher"):
            self.verify(trust=trust)

    def test_unknown_key_rejected(self):
        manifest = dict(self.manifest, key_id="untrusted-key")
        with self.assertRaisesRegex(ValueError, "Unknown key"):
            self.verify(manifest=manifest)

    def test_revoked_key_rejected(self):
        trust = json.loads(json.dumps(self.trust))
        trust["publishers"][0]["keys"][0]["state"] = "revoked"
        with self.assertRaisesRegex(ValueError, "revoked"):
            self.verify(trust=trust)

    def test_blocked_pack_digest_rejected(self):
        trust = json.loads(json.dumps(self.trust))
        trust["publishers"][0]["blocked_pack_sha256"].append(hashlib.sha256(self.pack).hexdigest())
        with self.assertRaisesRegex(ValueError, "explicitly blocked"):
            self.verify(trust=trust)

    def test_minimum_issuance_policy_rejected(self):
        trust = json.loads(json.dumps(self.trust))
        trust["publishers"][0]["minimum_issued_at"] = "2026-03-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "predates"):
            self.verify(trust=trust)

    def test_expiry_and_future_issuance_rejected(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            self.verify(now=datetime(2027, 2, 1, tzinfo=timezone.utc))
        with self.assertRaisesRegex(ValueError, "not yet valid"):
            self.verify(now=datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_issued_pack_after_signed_manifest_is_rejected(self):
        modified = json.loads(self.pack)
        modified["issued_at"] = "2026-02-15T00:00:00Z"
        newer = json_bytes(modified)
        manifest = sign_bytes(newer, self.private_pem, publisher="example-publisher",
                              key_id="key-1", issued_at="2026-03-01T00:00:00Z",
                              expires_at="2027-01-01T00:00:00Z", now=NOW)
        manifest["issued_at"] = "2026-02-01T00:00:00Z"
        # Metadata tampering invalidates signature.
        with self.assertRaisesRegex(ValueError, "signature invalid"):
            self.verify(pack=newer, manifest=manifest)

    def test_duplicate_manifest_fields_rejected(self):
        duplicate = json_bytes(self.manifest).replace(
            b'"publisher":', b'"publisher":"spoof","publisher":', 1)
        with self.assertRaisesRegex(ValueError, "strict UTF-8 JSON"):
            verify_bytes(self.pack, duplicate, json_bytes(self.trust), now=NOW)

    def test_unsupported_algorithm_rejected(self):
        trust = json.loads(json.dumps(self.trust))
        trust["publishers"][0]["keys"][0]["algorithm"] = "rsa"
        with self.assertRaisesRegex(ValueError, "Unsupported trust key"):
            self.verify(trust=trust)

    def test_trust_store_invalid_shape_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported trust-store"):
            self.verify(trust={"schema": TRUST_SCHEMA, "publishers": [], "auto_trust": True})

    def test_signed_manifest_missing_field_rejected(self):
        manifest = dict(self.manifest)
        manifest.pop("expires_at")
        with self.assertRaisesRegex(ValueError, "manifest fields"):
            self.verify(manifest=manifest)

    def test_load_pack_bytes_rejects_future_dated_pack(self):
        newer = json.loads(self.pack)
        newer["issued_at"] = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        with self.assertRaisesRegex(ValueError, "future"):
            load_pack_bytes(json_bytes(newer))

    def test_symlink_snapshot_rejected(self):
        regular = self.root / "ioc.json"
        regular.write_bytes(self.pack)
        link = self.root / "symlink"
        try:
            link.symlink_to(regular)
        except (OSError, NotImplementedError):
            self.skipTest("No symlink support")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            read_snapshot(link, 2_000_000)

    def test_private_key_not_world_readable(self):
        key = self.root / "secret.pem"
        key.write_bytes(self.private_pem)
        key.chmod(0o644)
        if __import__("os").name == "posix":
            with self.assertRaisesRegex(ValueError, "owner-only"):
                read_snapshot(key, 16_384, private=True)
        key.chmod(0o600)
        self.assertEqual(read_snapshot(key, 16_384, private=True), self.private_pem)

    def test_cli_verify_and_scan_requires_trust(self):
        pack_path = self.root / "ioc.json"
        manifest_path = self.root / "ioc.sig.json"
        trust_path = self.root / "trust.json"
        observation_path = self.root / "obs.json"
        pack_path.write_bytes(self.pack)
        manifest_path.write_bytes(json_bytes(self.manifest))
        trust_path.write_bytes(json_bytes(self.trust))
        observation_path.write_bytes(json_bytes({"schema": "fieldshield.observations.v1",
            "observations": [{"kind": "domain", "value": "spyware-demo.example.invalid"}]}))
        # CLI requires real-time validity: fixture expires in 2027.
        common = ["--pack", str(pack_path), "--signature", str(manifest_path),
                  "--trust", str(trust_path)]
        self.assertEqual(main(["verify", *common]), 0)
        self.assertEqual(main(["scan", *common, "observations", str(observation_path)]), 1)
        self.assertEqual(len(list(self.root.iterdir())), 4)

    def test_invalid_signature_prevents_scan(self):
        pack_path = self.root / "ioc.json"
        manifest_path = self.root / "ioc.sig.json"
        trust_path = self.root / "trust.json"
        pack_path.write_bytes(self.pack)
        manifest_path.write_bytes(b'{"schema": "fieldshield.signed-ioc.v1"}')
        trust_path.write_bytes(json_bytes(self.trust))
        self.assertEqual(main(["verify", "--pack", str(pack_path),
                               "--signature", str(manifest_path),
                               "--trust", str(trust_path)]), 2)


if __name__ == "__main__":
    unittest.main()
