#!/usr/bin/env python3
"""FieldShield Sentinel: offline, consensual IOC matching of local evidence.

This is NOT a live-device infection detector or forensic acquisition tool.
No subprocesses, network libraries, external dependencies, or implicit writes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

VERSION = "0.1.0"
SCHEMA = "fieldshield.sentinel.v1"
MAX_PACK_BYTES = 2_000_000
MAX_OBSERVATION_BYTES = 8_000_000
MAX_FILES = 10_000
MAX_HASH_BYTES = 100_000_000
MAX_FINDINGS = 1_000
KINDS = frozenset({"sha256", "domain", "url", "path", "process", "bundle_id"})
CONFIDENCES = frozenset({"low", "medium", "high"})
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _read_json(path: Path, limit: int) -> object:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be a regular, non-symlink file")
    if path.stat().st_size > limit:
        raise ValueError("Input exceeds size limit")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds size limit")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Input must contain valid UTF-8 JSON") from exc


def _normalize(kind: str, value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("Invalid indicator value")
    value = value.strip()
    if kind == "sha256":
        if not SHA256_RE.fullmatch(value):
            raise ValueError("Invalid SHA-256 indicator")
        return value.lower()
    if kind == "domain":
        value = value.rstrip(".").lower()
        if (not value or len(value) > 253 or "/" in value or ":" in value
                or not re.fullmatch(r"[a-z0-9.-]+", value)):
            raise ValueError("Invalid domain indicator")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
            raise ValueError("Invalid domain labels")
        return value
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Only HTTP(S) URLs without credentials are supported")
        if any(char.isspace() for char in value):
            raise ValueError("Whitespace is not supported in URL indicators")
        return value
    if kind == "path":
        value = value.replace("\\", "/")
        if value.startswith("/") or re.match(r"^[a-zA-Z]:", value) or any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("Path indicators must be exact relative paths")
        return value
    if kind in {"process", "bundle_id"}:
        return value
    raise ValueError("Unknown indicator type")


def load_pack(pack_path: Path) -> tuple[dict, dict]:
    """Load a single bounded snapshot; do not re-open the pack for its digest."""
    path = Path(pack_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Pack must be a regular non-symlink file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_PACK_BYTES + 1)
    return load_pack_bytes(raw)


def load_pack_bytes(raw: bytes) -> tuple[dict, dict]:
    """Validate exact in-memory bytes so authenticated and parsed data coincide."""
    if not isinstance(raw, bytes) or len(raw) > MAX_PACK_BYTES:
        raise ValueError("Pack exceeds size limit")
    try:
        pack = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid UTF-8 JSON indicator pack") from exc
    if not isinstance(pack, dict) or pack.get("schema") != "fieldshield.ioc-pack.v1":
        raise ValueError("Unsupported indicator pack schema")
    source = pack.get("source")
    issued = pack.get("issued_at")
    indicators = pack.get("indicators")
    if not isinstance(source, str) or not source.strip() or not isinstance(issued, str):
        raise ValueError("Pack needs source and issued_at provenance")
    if not isinstance(indicators, list) or not 0 < len(indicators) <= 100_000:
        raise ValueError("Indicator pack needs 1-100000 indicators")
    try:
        issued_date = datetime.fromisoformat(issued.replace("Z", "+00:00"))
        if issued_date.tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("issued_at requires a timezone-aware ISO datetime") from exc
    if issued_date > datetime.now(timezone.utc):
        raise ValueError("Indicator pack issued_at is in the future")
    lookup: dict[tuple[str, str], list[dict]] = {}
    ids: set[str] = set()
    for entry in indicators:
        if not isinstance(entry, dict):
            raise ValueError("Invalid indicator record")
        identifier, kind, value = entry.get("id"), entry.get("kind"), entry.get("value")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", identifier) or identifier in ids:
            raise ValueError("Indicator IDs must be unique, stable and safe")
        if kind not in KINDS:
            raise ValueError("Unsupported indicator type")
        if entry.get("confidence") not in CONFIDENCES:
            raise ValueError("Indicator confidence must be low/medium/high")
        if not isinstance(entry.get("reference"), str) or not entry["reference"].startswith("https://"):
            raise ValueError("Each indicator requires an HTTPS provenance reference")
        normalized = _normalize(kind, value)
        ids.add(identifier)
        lookup.setdefault((kind, normalized), []).append(entry)
    metadata = {"pack_sha256": hashlib.sha256(raw).hexdigest(),
                "source": source, "issued_at": issued, "indicators_loaded": len(ids)}
    return metadata, lookup


def _new_report(mode: str, metadata: dict) -> dict:
    return {"schema": SCHEMA, "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode, "indicator_pack": metadata,
            "counts": {"inspected": 0, "findings": 0, "uninspected": 0},
            "findings": [], "uninspected": [], "excluded": [],
            "limitations": ["Indicator matching is not proof of infection or absence of spyware.",
                            "This tool does not acquire live mobile-device evidence.",
                            "Provenance URLs are labels, not independently verified by this program."],
            "network_access": False, "wrote_files": False}


def _record(report: dict, lookup: dict, kind: str, value: str, location: dict) -> None:
    try:
        normalized = _normalize(kind, value)
    except ValueError:
        return
    for match in lookup.get((kind, normalized), ()):
        if len(report["findings"]) >= MAX_FINDINGS:
            if not any(e.get("reason") == "finding-count-limit" for e in report["uninspected"]):
                report["uninspected"].append({"reason": "finding-count-limit"})
            return
        report["findings"].append({"indicator_id": match["id"], "kind": kind,
                                   "confidence": match["confidence"], "reference": match["reference"],
                                   "location": location})


def _finalize(report: dict) -> dict:
    report["counts"]["findings"] = len(report["findings"])
    report["counts"]["uninspected"] = len(report["uninspected"])
    report["decision"] = ("INCOMPLETE" if report["uninspected"] or not report["counts"]["inspected"]
                          else "INDICATORS_FOUND" if report["findings"] else "NO_MATCHES_IN_SCOPE")
    return report


def scan_files(target: Path, metadata: dict, lookup: dict,
               max_files: int = MAX_FILES, max_hash_bytes: int = MAX_HASH_BYTES) -> dict:
    """Only hashes bounded regular files and checks exact relative filenames."""
    target = Path(target).expanduser()
    if target.is_symlink() or not (target.is_file() or target.is_dir()):
        raise ValueError("Target must be a regular file or directory, not a symlink")
    report = _new_report("files", metadata)
    root = target.resolve()
    candidates = [root] if root.is_file() else []
    if root.is_dir():
        def onerror(error: OSError) -> None:
            report["uninspected"].append({"reason": "directory-read-error"})
        for folder, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
            dirs[:] = [d for d in sorted(dirs) if d != ".git"]
            for directory in dirs:
                if (Path(folder) / directory).is_symlink():
                    report["uninspected"].append({"reason": "symlink-directory"})
            dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
            for name in sorted(files):
                if len(candidates) >= max_files:
                    report["uninspected"].append({"reason": "file-count-limit"})
                    return _scan_candidates(candidates, root, report, lookup, max_hash_bytes)
                candidates.append(Path(folder) / name)
    return _scan_candidates(candidates, root, report, lookup, max_hash_bytes)


def _scan_candidates(candidates: list[Path], root: Path, report: dict,
                     lookup: dict, max_hash_bytes: int) -> dict:
    for file in candidates:
        rel = file.name if root.is_file() else file.relative_to(root).as_posix()
        if file.is_symlink() or not file.is_file():
            report["uninspected"].append({"reason": "non-regular-or-symlink", "path": rel})
            continue
        try:
            size = file.stat().st_size
            if size > max_hash_bytes:
                report["uninspected"].append({"reason": "file-size-limit", "path": rel})
                continue
            digest = hashlib.sha256()
            read = 0
            with file.open("rb") as handle:
                while True:
                    chunk = handle.read(min(1024 * 1024, max_hash_bytes - read + 1))
                    if not chunk:
                        break
                    read += len(chunk)
                    if read > max_hash_bytes:
                        break
                    digest.update(chunk)
            if read != size or read > max_hash_bytes:
                report["uninspected"].append({"reason": "changed-or-too-large", "path": rel})
                continue
        except OSError:
            report["uninspected"].append({"reason": "read-error", "path": rel})
            continue
        report["counts"]["inspected"] += 1
        _record(report, lookup, "sha256", digest.hexdigest(), {"path": rel})
        _record(report, lookup, "path", rel, {"path": rel})
    report["excluded"].append(".git directory contents (intentional scope exclusion)")
    return _finalize(report)


def scan_observations(path: Path, metadata: dict, lookup: dict) -> dict:
    """Match explicitly typed observations, without copying their raw values to reports.

    Input format: JSON object {"schema":"fieldshield.observations.v1", "observations":
      [{"kind":"domain", "value":"example.invalid"}, ...]}
    """
    payload = _read_json(Path(path), MAX_OBSERVATION_BYTES)
    if not isinstance(payload, dict) or payload.get("schema") != "fieldshield.observations.v1" or not isinstance(payload.get("observations"), list):
        raise ValueError("Unsupported observation schema")
    observations = payload["observations"]
    if len(observations) > 100_000:
        raise ValueError("Too many observations")
    report = _new_report("observations", metadata)
    for index, obs in enumerate(observations):
        if not isinstance(obs, dict) or obs.get("kind") not in KINDS or not isinstance(obs.get("value"), str):
            report["uninspected"].append({"index": index, "reason": "invalid-observation"})
            continue
        try:
            _normalize(obs["kind"], obs["value"])
        except ValueError:
            report["uninspected"].append({"index": index, "reason": "invalid-value"})
            continue
        report["counts"]["inspected"] += 1
        _record(report, lookup, obs["kind"], obs["value"], {"index": index})
        if obs["kind"] == "url":
            hostname = urlsplit(obs["value"]).hostname
            if hostname:
                _record(report, lookup, "domain", hostname, {"index": index})
    return _finalize(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FieldShield Sentinel offline evidence matcher")
    parser.add_argument("mode", choices=("files", "observations"))
    parser.add_argument("target", type=Path)
    parser.add_argument("--iocs", required=True, type=Path, help="local, reviewed JSON indicator pack")
    parser.add_argument("--output", type=Path, help="explicitly save JSON report; default stdout only")
    args = parser.parse_args(argv)
    try:
        metadata, lookup = load_pack(args.iocs)
        report = (scan_files(args.target, metadata, lookup) if args.mode == "files"
                  else scan_observations(args.target, metadata, lookup))
        if args.output:
            report["wrote_files"] = True
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return {"NO_MATCHES_IN_SCOPE": 0, "INDICATORS_FOUND": 1, "INCOMPLETE": 2}[report["decision"]]
    except (ValueError, OSError) as exc:
        print("Sentinel error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
