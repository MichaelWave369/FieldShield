#!/usr/bin/env python3
"""FieldShield Sentinel v0.2: intentionally narrow, offline STIX 2.1 import.

Only literal, single-comparison STIX patterns are converted. Unsupported
patterns stop the entire conversion rather than changing detection semantics.
No downloading, execution, privileged access, or implicit file writes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from sentinel import _normalize

MAX_BUNDLE_BYTES = 8_000_000
MAX_OBJECTS = 20_000

# Deliberately NOT a STIX expression interpreter. Anything other than one
# quoted equality comparison is refused, including OR, AND, qualifiers,
# escaping, wildcards, START/STOP, FOLLOWEDBY, LIKE, MATCHES, etc.
SIMPLE_PATTERN = re.compile(
    r"""\[\s*(?P<field>domain-name:value|url:value|file:hashes\.'SHA-256'|process:name|app:id)\s*=\s*'(?P<value>[^'\\]{1,2048})'\s*\]"""
)
FIELD_TO_KIND = {
    "domain-name:value": "domain",
    "url:value": "url",
    "file:hashes.'SHA-256'": "sha256",
    "process:name": "process",
    "app:id": "bundle_id",  # MVT-specific extension, not a core STIX SCO.
}
INDICATOR_ID = re.compile(
    r"indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def read_bundle(path: Path) -> tuple[dict, str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("STIX input must be a regular, non-symlink local file")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("STIX input exceeds 8 MB limit")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("STIX input exceeds 8 MB limit")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("STIX input must be valid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("STIX bundle must be a JSON object")
    return obj, hashlib.sha256(raw).hexdigest()


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(label + " must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(label + " must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(label + " must include timezone")
    return parsed.astimezone(timezone.utc)


def _source_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username
                or parts.password or any(c.isspace() for c in value)):
            raise ValueError("source reference must be an HTTPS URL without credentials")
    except ValueError as exc:
        raise ValueError("source reference must be an HTTPS URL without credentials") from exc
    if len(value) > 2048:
        raise ValueError("source reference is too long")
    return value


def _source_label(label: str) -> str:
    if not label or len(label) > 120 or any(ord(c) < 32 for c in label):
        raise ValueError("source name must contain 1-120 printable characters")
    return label


def _confidence(value: object) -> str:
    # A missing STIX score is unknown, mapped conservatively to LOW;
    # this is not a probability of compromise.
    if value is None:
        return "low"
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError("STIX confidence must be an integer between 0 and 100")
    return "high" if value >= 80 else "medium" if value >= 40 else "low"


def convert_bundle(bundle: object, *, source_name: str, reference_url: str,
                   bundle_sha256: str, now: datetime | None = None) -> dict:
    """Convert only fully understood, currently valid, exact-match patterns.

    Any active unsupported indicator rejects the complete bundle. Revoked,
    expired, and not-yet-active indicators are omitted with counts in provenance.
    """
    source_name = _source_label(source_name)
    reference_url = _source_url(reference_url)
    if not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
        raise ValueError("bundle_sha256 must be a lowercase SHA-256")
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("Expected a STIX bundle object")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or len(objects) > MAX_OBJECTS:
        raise ValueError("STIX bundle objects must be a bounded list")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)

    indicators = []
    seen: set[str] = set()
    skipped = {"revoked": 0, "expired": 0, "not_yet_active": 0,
               "non_indicator_objects": 0}
    unsupported = []
    for obj in objects:
        if not isinstance(obj, dict):
            raise ValueError("STIX bundle contains a non-object entry")
        if obj.get("type") != "indicator":
            skipped["non_indicator_objects"] += 1
            continue
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or not INDICATOR_ID.fullmatch(stix_id):
            raise ValueError("STIX indicator requires a correctly formatted ID")
        stix_id = stix_id.lower()
        if stix_id in seen:
            raise ValueError("Duplicate STIX indicator ID; version resolution is not implemented")
        seen.add(stix_id)
        if obj.get("spec_version") != "2.1":
            unsupported.append(stix_id + ": not STIX 2.1")
            continue
        if obj.get("revoked") is True:
            skipped["revoked"] += 1
            continue
        # STIX indicator valid_from is required; missing or malformed validity
        # must never silently become a continuously valid rule.
        valid_from = _utc_timestamp(obj.get("valid_from"), "valid_from")
        valid_until = (_utc_timestamp(obj["valid_until"], "valid_until")
                       if "valid_until" in obj else None)
        if valid_until and valid_until <= valid_from:
            raise ValueError("STIX indicator valid_until is not after valid_from")
        if valid_until and valid_until <= now:
            skipped["expired"] += 1
            continue
        if valid_from > now:
            skipped["not_yet_active"] += 1
            continue
        if obj.get("pattern_type") != "stix" or obj.get("pattern_version", "2.1") != "2.1":
            unsupported.append(stix_id + ": unsupported pattern type/version")
            continue
        pattern = obj.get("pattern")
        match = SIMPLE_PATTERN.fullmatch(pattern) if isinstance(pattern, str) else None
        if not match:
            unsupported.append(stix_id + ": complex or unsupported pattern")
            continue
        kind = FIELD_TO_KIND[match["field"]]
        try:
            value = _normalize(kind, match["value"])
            confidence = _confidence(obj.get("confidence"))
        except ValueError as exc:
            unsupported.append(stix_id + ": invalid value or confidence (" + str(exc) + ")")
            continue
        indicators.append({"id": stix_id, "kind": kind, "value": value,
                           "confidence": confidence, "reference": reference_url})
    if unsupported:
        sample = "; ".join(unsupported[:3])
        raise ValueError(
            f"Refusing partial import: {len(unsupported)} active indicator(s) unsupported. "
            + sample + ("; ..." if len(unsupported) > 3 else "")
        )
    if not indicators:
        raise ValueError("No supported currently valid STIX indicators to import")
    if len(indicators) > 100_000:
        raise ValueError("Too many converted indicators")
    result = {
        "schema": "fieldshield.ioc-pack.v1",
        "source": f"{source_name} | input SHA-256 {bundle_sha256}",
        "issued_at": now.isoformat(),
        "indicators": indicators,
        "origin_stix": {
            "bundle_sha256": bundle_sha256,
            "indicators_imported": len(indicators),
            "counts_not_imported": skipped,
            "source_reference": reference_url,
            "scope": "STIX 2.1 literal single-comparison patterns only",
            "warning": "Locally imported intelligence is not independently verified or signed.",
        },
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a reviewed local STIX 2.1 bundle into a Sentinel IOC pack"
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--source", required=True, help="human-reviewed feed identity")
    parser.add_argument("--reference", required=True, help="HTTPS source documentation URL")
    parser.add_argument("--output", type=Path,
                        help="explicitly create a new output pack; default stdout only")
    args = parser.parse_args(argv)
    try:
        bundle, digest = read_bundle(args.bundle)
        pack = convert_bundle(bundle, source_name=args.source,
                              reference_url=args.reference, bundle_sha256=digest)
        content = json.dumps(pack, indent=2, ensure_ascii=True) + "\n"
        if args.output is not None:
            if args.output.is_symlink():
                raise ValueError("Refusing symlink output")
            # Exclusive create, no silent overwrites.
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(content)
            print(f"Created pack with {len(pack['indicators'])} indicator(s): {args.output}")
        else:
            print(content, end="")
        return 0
    except (OSError, ValueError) as exc:
        print("STIX import refused: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
