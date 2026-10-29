#!/usr/bin/env python3
"""Φ Sentinel Verified Packs v0.3: offline Ed25519 provenance gate.

Opt-in verified commands do not silently fall back to unsigned packs.
The existing sentinel.py CLI remains usable without this optional dependency.
Trust roots must be pinned locally by an informed human.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from sentinel import MAX_PACK_BYTES, load_pack_bytes, scan_files, scan_observations, _strict_json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
except ImportError as exc:
    raise SystemExit(
        "Verified pack mode needs optional dependency: pip install -r requirements-verified.txt"
    ) from exc

VERSION = "0.3.0"
MANIFEST_SCHEMA = "fieldshield.signed-ioc.v1"
TRUST_SCHEMA = "fieldshield.trust-store.v1"
DOMAIN = b"FieldShield Sentinel Signed IOC v1\x00"
MAX_MANIFEST = 16_384
MAX_TRUST = 131_072
MAX_KEY_PEM = 16_384
ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEADER_FIELDS = frozenset({"schema", "publisher", "key_id", "pack_sha256",
                           "issued_at", "expires_at"})
SIGNATURE_FIELDS = HEADER_FIELDS | {"signature_b64"}


def read_snapshot(path: Path, limit: int, *, private: bool = False) -> bytes:
    """Bounded snapshot from a regular file, with best-effort symlink refusal."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing symbolic link input")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Input must be a regular file")
        if private and os.name == "posix" and stat.S_IMODE(before.st_mode) & 0o077:
            raise ValueError("Private key file must be owner-only (chmod 600)")
        if before.st_size > limit:
            raise ValueError("Input exceeds size limit")
        with os.fdopen(os.dup(fd), "rb") as handle:
            raw = handle.read(limit + 1)
        after = os.fstat(fd)
        if (len(raw) > limit or len(raw) != before.st_size or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns):
            raise ValueError("Input too large or changed during read")
        if path.is_symlink():
            raise ValueError("Input changed to a symbolic link")
        return raw
    finally:
        os.close(fd)


def _json(data: bytes, label: str) -> dict:
    """Use the same strict JSON contract for signed manifests and trust roots."""
    return _strict_json(data, label)


def _date(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(label + " must be a timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(label + " must be ISO-8601") from exc
    if dt.tzinfo is None:
        raise ValueError(label + " must include a timezone")
    return dt.astimezone(timezone.utc)


def _b64(value: object, expected_size: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(label + " must be base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(label + " is invalid base64") from exc
    if len(decoded) != expected_size:
        raise ValueError(label + " has an unexpected byte length")
    return decoded


def _check_header(header: object, *, signed: bool, now: datetime) -> tuple[datetime, datetime]:
    if not isinstance(header, dict) or set(header) != (SIGNATURE_FIELDS if signed else HEADER_FIELDS):
        raise ValueError("Signed manifest fields do not match v1 schema")
    if header["schema"] != MANIFEST_SCHEMA:
        raise ValueError("Unsupported signed manifest schema")
    for field in ("publisher", "key_id"):
        if not isinstance(header[field], str) or not ID.fullmatch(header[field]):
            raise ValueError("Invalid " + field)
    digest = header["pack_sha256"]
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError("Invalid pack_sha256")
    issued = _date(header["issued_at"], "issued_at")
    expires = _date(header["expires_at"], "expires_at")
    if expires <= issued:
        raise ValueError("expires_at must be after issued_at")
    if issued > now:
        raise ValueError("Signed manifest not yet valid")
    if now >= expires:
        raise ValueError("Signed manifest expired")
    if signed:
        _b64(header["signature_b64"], 64, "signature")
    return issued, expires


def _signed_bytes(header: dict) -> bytes:
    # Domain separated, exact JSON serialization of authenticated manifest fields.
    return DOMAIN + json.dumps(header, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")


def _trusted_key(store: dict, publisher: str, key_id: str, pack_digest: str,
                 issued: datetime) -> bytes:
    if set(store) != {"schema", "publishers"} or store["schema"] != TRUST_SCHEMA:
        raise ValueError("Unsupported trust-store schema")
    publishers = store["publishers"]
    if not isinstance(publishers, list) or len(publishers) > 100:
        raise ValueError("Trust store publishers must be a bounded list")
    seen_publishers = set()
    selected = None
    for entry in publishers:
        if not isinstance(entry, dict) or set(entry) != {
            "id", "keys", "blocked_pack_sha256", "minimum_issued_at"
        }:
            raise ValueError("Invalid publisher trust policy")
        identifier = entry["id"]
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in seen_publishers:
            raise ValueError("Invalid or duplicate trust publisher")
        seen_publishers.add(identifier)
        if identifier == publisher:
            selected = entry
    if selected is None:
        raise ValueError("Unknown publisher; no automatic trust")
    blocked = selected["blocked_pack_sha256"]
    if not isinstance(blocked, list) or any(not isinstance(x, str) or not DIGEST.fullmatch(x) for x in blocked):
        raise ValueError("Invalid blocked pack digests")
    if pack_digest in blocked:
        raise ValueError("Pack digest explicitly blocked by local trust policy")
    minimum = _date(selected["minimum_issued_at"], "minimum_issued_at")
    if issued < minimum:
        raise ValueError("Pack predates local trust policy minimum")
    keys = selected["keys"]
    if not isinstance(keys, list) or len(keys) > 100:
        raise ValueError("Trust store keys must be a bounded list")
    seen = set()
    candidate = None
    for item in keys:
        if not isinstance(item, dict) or set(item) != {"id", "algorithm", "state", "public_key_b64"}:
            raise ValueError("Invalid trust key policy")
        ident = item["id"]
        if not isinstance(ident, str) or not ID.fullmatch(ident) or ident in seen:
            raise ValueError("Duplicate or invalid trust key ID")
        seen.add(ident)
        if item["algorithm"] != "ed25519" or item["state"] not in ("trusted", "revoked"):
            raise ValueError("Unsupported trust key algorithm or state")
        raw = _b64(item["public_key_b64"], 32, "public_key_b64")
        if ident == key_id:
            if item["state"] == "revoked":
                raise ValueError("Signing key revoked")
            candidate = raw
    if candidate is None:
        raise ValueError("Unknown key; no automatic trust")
    return candidate


def verify_bytes(pack_bytes: bytes, signature_bytes: bytes, trust_bytes: bytes,
                 *, now: datetime | None = None) -> tuple[dict, dict]:
    """Verify exact supplied pack bytes and then compile these same bytes."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Verification clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if len(pack_bytes) > MAX_PACK_BYTES:
        raise ValueError("Pack exceeds size limit")
    header = _json(signature_bytes, "Signature manifest")
    issued, _ = _check_header(header, signed=True, now=now)
    digest = hashlib.sha256(pack_bytes).hexdigest()
    if header["pack_sha256"] != digest:
        raise ValueError("IOC pack digest mismatch")
    store = _json(trust_bytes, "Trust store")
    key = _trusted_key(store, header["publisher"], header["key_id"], digest, issued)
    auth_header = {k: header[k] for k in HEADER_FIELDS}
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            _b64(header["signature_b64"], 64, "signature"), _signed_bytes(auth_header))
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature invalid") from exc
    metadata, lookup = load_pack_bytes(pack_bytes)
    if _date(metadata["issued_at"], "IOC pack issued_at") > issued:
        raise ValueError("IOC pack claims an issue date after its signed manifest")
    metadata["verification"] = {
        "status": "ed25519-verified",
        "publisher": header["publisher"], "key_id": header["key_id"],
        "public_key_sha256": hashlib.sha256(key).hexdigest(),
        "manifest_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "trust_store_sha256": hashlib.sha256(trust_bytes).hexdigest(),
        "expires_at": header["expires_at"],
        "warning": "Signature authenticates the locally trusted key, not accuracy of spyware claims.",
    }
    return metadata, lookup


def sign_bytes(pack_bytes: bytes, private_key_pem: bytes, *,
               publisher: str, key_id: str, issued_at: str, expires_at: str,
               now: datetime | None = None) -> dict:
    """Offline author-side signing; callers must protect their own private keys."""
    now = now or datetime.now(timezone.utc)
    metadata, _ = load_pack_bytes(pack_bytes)
    header = {"schema": MANIFEST_SCHEMA, "publisher": publisher, "key_id": key_id,
              "pack_sha256": hashlib.sha256(pack_bytes).hexdigest(),
              "issued_at": issued_at, "expires_at": expires_at}
    signed_at, _ = _check_header(header, signed=False, now=now)
    if _date(metadata["issued_at"], "Pack issued_at") > signed_at:
        raise ValueError("Cannot sign a pack dated after the manifest issue date")
    try:
        private = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid or encrypted PEM private key") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Only Ed25519 private keys are supported")
    signature = private.sign(_signed_bytes(header))
    return {**header, "signature_b64": base64.b64encode(signature).decode("ascii")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Φ Sentinel v0.3 offline signed intelligence")
    sub = parser.add_subparsers(dest="command", required=True)
    sign = sub.add_parser("sign", help="sign a reviewed IOC pack with an existing local Ed25519 key")
    sign.add_argument("--pack", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--publisher", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--expires-at", required=True, help="ISO timestamp with timezone")
    sign.add_argument("--output", type=Path, help="write a NEW signature manifest; defaults to stdout")
    for command in ("verify", "scan"):
        cmd = sub.add_parser(command, help="verify signed local IOC pack" + (" and scan" if command == "scan" else ""))
        cmd.add_argument("--pack", type=Path, required=True)
        cmd.add_argument("--signature", type=Path, required=True)
        cmd.add_argument("--trust", type=Path, required=True)
        if command == "scan":
            cmd.add_argument("mode", choices=("files", "observations"))
            cmd.add_argument("target", type=Path)
    args = parser.parse_args(argv)
    try:
        pack = read_snapshot(args.pack, MAX_PACK_BYTES)
        if args.command == "sign":
            private = read_snapshot(args.private_key, MAX_KEY_PEM, private=True)
            now = datetime.now(timezone.utc)
            manifest = sign_bytes(pack, private, publisher=args.publisher, key_id=args.key_id,
                                  issued_at=now.isoformat(), expires_at=args.expires_at, now=now)
            result = json.dumps(manifest, indent=2) + "\n"
            if args.output:
                with args.output.open("x", encoding="utf-8") as handle:
                    handle.write(result)
                print(f"Created signature manifest: {args.output}")
            else:
                print(result, end="")
            return 0
        metadata, lookup = verify_bytes(
            pack, read_snapshot(args.signature, MAX_MANIFEST),
            read_snapshot(args.trust, MAX_TRUST))
        if args.command == "verify":
            print(json.dumps({"verified": True, "indicator_pack": metadata}, indent=2))
            return 0
        report = (scan_files(args.target, metadata, lookup) if args.mode == "files"
                  else scan_observations(args.target, metadata, lookup))
        print(json.dumps(report, indent=2))
        return {"NO_MATCHES_IN_SCOPE": 0, "INDICATORS_FOUND": 1, "INCOMPLETE": 2}[report["decision"]]
    except (OSError, ValueError) as exc:
        print("Sentinel verified mode refused: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
