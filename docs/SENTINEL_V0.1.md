# Φ Sentinel v0.1: Offline forensic evidence matching

Sentinel is an **experimental, independent, standard-library-only** extension of
FieldShield. It checks **user-provided local evidence** against **user-reviewed,
local indicator packs**. It is NOT a live spyware detector, mobile extractor,
antivirus replacement, or forensic certificate. The bundled rules are entirely
synthetic, and will not detect real-world spyware.

## Quick start

Python 3.10+; no pip install. From the FieldShield repository root:

    python sentinel.py observations examples/synthetic-observations.json --iocs rules/sentinel-demo-iocs.json
    python sentinel.py files examples --iocs rules/sentinel-demo-iocs.json
    python -m unittest discover -s tests -v

To intentionally save a report, add:

    --output local-report.json

Default operation writes no report file, makes no network requests, executes no
downloaded code, and attempts no privilege escalation. It does not check
operating-system permission dialogs or prevent normal interpreter behavior.
The operator must own or have informed permission to analyze the evidence.

## Input format

Only explicitly typed JSON observations are supported:

    {
      "schema": "fieldshield.observations.v1",
      "observations": [
        {"kind": "domain", "value": "spyware-demo.example.invalid"}
      ]
    }

An indicator pack contains source provenance and an issued timestamp:

    {
      "schema": "fieldshield.ioc-pack.v1",
      "source": "Research source and publication details",
      "issued_at": "2026-01-01T00:00:00Z",
      "indicators": [{
        "id": "SYNTHETIC-001", "kind": "domain",
        "value": "spyware-demo.example.invalid",
        "confidence": "low",
        "reference": "https://www.rfc-editor.org/rfc/rfc2606"
      }]
    }

Supported indicator kinds: sha256, path, domain, url, process, bundle_id.
All comparisons are exact, except that the hostname of a URL observation is
also checked against domain indicators. A files scan checks only SHA-256
digests and exact relative file paths; it does NOT inspect file content,
memory, running processes, mobile backups, or live network activity.

All matches report the indicator ID, source-supplied confidence, provenance
reference, and location, not raw matched values or file contents. Relative
path names may still be sensitive; do not share reports without review.
Source and reference strings are labels, not independently verified sources.

## Outcome semantics

- NO_MATCHES_IN_SCOPE (exit 0): No included indicators matched the inspected
  evidence. **Does NOT establish that a device is safe.**
- INDICATORS_FOUND (exit 1): One or more exact indicator matches. Review
  the source and evidence manually; no match alone proves infection.
- INCOMPLETE (exit 2): The inspection was incomplete, invalid, or limited.
  Findings may still be present and must not be ignored.

File-size, file-count, and findings limits apply. Symlinks are not followed;
.git directories are intentionally excluded. No auto-upload, removal,
quarantine, or telemetry is implemented.

## Next research milestones (not part of v0.1)

1. Reviewed STIX 2.1 subset importer with signed, license-checked rule packs.
2. Separate and consent-based adapters for documented MVT/AndroidQF forensic
   exports, independently tested against the current input schemas.
3. Threat-model hostile input, filesystem race conditions, and false positives;
   add reproducible fixtures and independently validate detection quality.
4. Optional YARA-X integration followed by a PhiOS Security Center interface,
   with PhiArk as an offline distribution channel.

## Relevant external references

- Amnesty MVT: https://docs.mvt.re/en/latest/introduction/
- MVT IOC support: https://docs.mvt.re/en/stable/iocs/
- STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- Amnesty 2026 assessment: https://securitylab.amnesty.org/latest/2026/08/strengthening-the-tools-behind-consensual-forensics-secure-design-assessment/

**FieldShield rule: no unsupported claims, no hidden uploads, no automatic
attribution to a vendor or government, and no clean-device guarantee.**
