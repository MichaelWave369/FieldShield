#!/usr/bin/env python3
"""FieldShield v0.1: offline, non-executing static inspection of untrusted source trees.

No dependencies outside the Python standard library. Heuristic findings are
not proof of malicious intent or an assurance that unflagged code is safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

VERSION = "0.1.0"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000
MAX_FINDINGS_PER_FILE = 40
IGNORE_DIRS = frozenset({".git"})

# Rule ID, severity, explanation, regular expression.
RULES = (
    ("PIPE_TO_SHELL", "high", "Network-download command piped to a shell",
     re.compile(r"(?i)\b(?:curl|wget)\b[^\n]{0,160}\|\s*(?:bash|sh|zsh)\b")),
    ("DESTRUCTIVE_ROOT_COMMAND", "high", "Potentially destructive root-path shell command",
     re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/(?:\s|$)")),
    ("PROMPT_HIERARCHY_OVERRIDE", "high", "Text resembling an instruction-hierarchy override",
     re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
    ("PROMPT_SECRET_DISCLOSURE", "high", "Instruction resembling a request to expose hidden prompts",
     re.compile(r"(?i)\b(?:reveal|print|expose|dump)\b[^\n]{0,70}\b(?:system\s+prompt|developer\s+message|hidden\s+instructions)\b")),
    ("PROMPT_GUARDRAIL_BYPASS", "medium", "Text resembling an attempt to bypass safeguards",
     re.compile(r"(?i)\b(?:disable|bypass|turn\s+off)\b[^\n]{0,40}\b(?:safety|security|guardrails|logging|audit(?:ing)?)\b")),
    ("SHELL_EXECUTION", "medium", "Shell execution enabled in source code",
     re.compile(r"\bshell\s*=\s*True\b")),
    ("SENSITIVE_CREDENTIAL_PATH", "medium", "Reference to a commonly sensitive credential file",
     re.compile(r"(?i)(?:\.ssh/id_rsa|\.aws/credentials)")),
)

INSTALL_LIFECYCLE_HOOKS = frozenset({
    "preinstall", "install", "postinstall", "prepare", "prepublish",
    "prepublishOnly", "prepack", "postpack",
})


def finding(file_path: str, file_hash: str, rule_id: str, severity: str,
            explanation: str, line: int) -> dict:
    return {
        "path": file_path, "sha256": file_hash, "line": line,
        "rule_id": rule_id, "severity": severity, "explanation": explanation,
    }


def scan_target(target: Path, *, max_file_bytes: int = MAX_FILE_BYTES,
                max_files: int = MAX_FILES) -> dict:
    """Inspect a file or directory without opening symlinks or executing code.

    A HOLD decision is mandatory when any part of the requested inspection is
    incomplete, or when high-severity findings are present.
    """
    target = Path(target).expanduser()
    if not target.exists() and not target.is_symlink():
        raise ValueError("Target does not exist")
    if target.is_symlink():
        raise ValueError("Refusing to scan a symlink target")
    if not (target.is_file() or target.is_dir()):
        raise ValueError("Target must be a regular file or directory")

    root = target.resolve()
    report = {
        "schema": "fieldshield.scan.v1",
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(root),
        "policy": {
            "max_file_bytes": max_file_bytes,
            "max_files": max_files,
            "ignored_directories": sorted(IGNORE_DIRS),
            "no_code_execution": True,
            "network_access": False,
        },
        "scanned_files": [],
        "findings": [],
        "uninspected": [],
        "disclaimer": "Heuristic signals, not proof of malicious intent or a safety guarantee.",
    }

    candidates = []
    if root.is_file():
        candidates.append(root)
    else:
        def walk_error(error: OSError) -> None:
            report["uninspected"].append({"path": str(error.filename), "reason": "directory-read-error"})

        for folder, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
            keep_dirs = []
            for name in sorted(dirs):
                path = Path(folder) / name
                if name in IGNORE_DIRS:
                    continue  # Explicit scope exclusion, documented in the receipt.
                if path.is_symlink():
                    report["uninspected"].append({"path": str(path.relative_to(root)), "reason": "symlink"})
                else:
                    keep_dirs.append(name)
            dirs[:] = keep_dirs
            for name in sorted(names):
                candidates.append(Path(folder) / name)
            if len(candidates) > max_files:
                break

    if len(candidates) > max_files:
        report["uninspected"].append({"path": ".", "reason": "file-count-limit"})
        candidates = candidates[:max_files]

    for path in candidates:
        rel = path.name if root.is_file() else str(path.relative_to(root))
        if path.is_symlink():
            report["uninspected"].append({"path": rel, "reason": "symlink"})
            continue
        if not path.is_file():
            report["uninspected"].append({"path": rel, "reason": "not-regular-file"})
            continue

        try:
            if path.stat().st_size > max_file_bytes:
                report["uninspected"].append({"path": rel, "reason": "file-size-limit"})
                continue
            # Read bounded files, but refuse content that changes size mid-read.
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                report["uninspected"].append({"path": rel, "reason": "file-size-limit"})
                continue
        except OSError:
            report["uninspected"].append({"path": rel, "reason": "read-error"})
            continue

        digest = hashlib.sha256(raw).hexdigest()
        try:
            content = raw.decode("utf-8")
            if "\x00" in content:
                raise UnicodeError("NUL-containing file")
        except UnicodeError:
            report["uninspected"].append({"path": rel, "reason": "non-utf8-or-binary", "sha256": digest})
            continue

        report["scanned_files"].append({"path": rel, "sha256": digest, "bytes": len(raw)})
        file_findings = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule_id, severity, explanation, pattern in RULES:
                if pattern.search(line):
                    file_findings.append(finding(rel, digest, rule_id, severity, explanation, line_number))
                    if len(file_findings) >= MAX_FINDINGS_PER_FILE:
                        break
            if len(file_findings) >= MAX_FINDINGS_PER_FILE:
                report["uninspected"].append({"path": rel, "reason": "findings-truncated"})
                break

        if path.name.lower() == "package.json":
            try:
                manifest = json.loads(content)
                scripts = manifest.get("scripts", {}) if isinstance(manifest, dict) else {}
                if isinstance(scripts, dict):
                    for hook in sorted(INSTALL_LIFECYCLE_HOOKS.intersection(scripts)):
                        file_findings.append(finding(
                            rel, digest, "NPM_INSTALL_HOOK", "high",
                            "package.json declares an executable installation/publishing hook: " + hook, 0,
                        ))
                else:
                    report["uninspected"].append({"path": rel, "reason": "invalid-package-scripts-shape"})
            except (ValueError, TypeError):
                report["uninspected"].append({"path": rel, "reason": "invalid-package-json"})

        report["findings"].extend(file_findings)

    has_high = any(item["severity"] == "high" for item in report["findings"])
    report["complete"] = not report["uninspected"] and bool(report["scanned_files"])
    if not report["complete"] or has_high:
        report["decision"] = "HOLD"
    elif report["findings"]:
        report["decision"] = "REVIEW"
    else:
        report["decision"] = "PASS"
    report["counts"] = {
        "files_scanned": len(report["scanned_files"]),
        "findings": len(report["findings"]),
        "uninspected": len(report["uninspected"]),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FieldShield static offline trust scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="inspect existing source without installing or running it")
    scan.add_argument("path", help="local file or directory to inspect")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output", type=Path, help="save full JSON receipt to a local file")
    scan.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    scan.add_argument("--max-files", type=int, default=MAX_FILES)
    args = parser.parse_args(argv)
    if args.max_file_bytes < 1 or args.max_files < 1:
        parser.error("limits must be positive")
    try:
        report = scan_target(Path(args.path), max_file_bytes=args.max_file_bytes,
                             max_files=args.max_files)
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (ValueError, OSError) as error:
        print("FieldShield scan failed: " + str(error), file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("FieldShield v" + VERSION + " | " + report["decision"])
        print("Scanned: {files_scanned} | Findings: {findings} | Uninspected: {uninspected}".format(
            **report["counts"]))
        for item in report["findings"]:
            print("  {severity}: {rule_id} at {path}:{line} ({explanation})".format(**item))
        for item in report["uninspected"]:
            print("  NOT INSPECTED: {path} ({reason})".format(**item))
        print("Signals are not proof of intent; PASS does not establish safety.")
    return {"PASS": 0, "REVIEW": 1, "HOLD": 2}[report["decision"]]


if __name__ == "__main__":
    raise SystemExit(main())
