# FieldShield ↔ PhiOS URL authority parity v2

**Scoped, deliberately conservative change.** Python `urllib.parse.urlsplit` and browser WHATWG `URL` disagree about certain URL host forms. In an exact-indicator matcher, silent parser repair could create different domain matches in the two runtimes.

The `_safe_url_hostname` gate now rejects potentially ambiguous authorities **before** signed URL IOC validation or observation matching:

- Percent-encoded hostnames (e.g. `ex%61mple.invalid`)
- Backslashes in authorities
- Raw Unicode hostnames (punycode is accepted if separately reviewed)
- IPv6 literals, numeric/IP-shortcut hosts, 0x-style IPv4 spellings
- Credentials, control characters and whitespace
- Malformed DNS labels and nonnumeric, oversized or out-of-range ports

Accepted URLs use ASCII DNS label syntax, with an optional colon followed by 1–5 decimal port digits (0–65535), and an alphabetic-starting final DNS label. Uppercase schemes/hosts, localhost, valid trailing-dot hostnames and percent escapes in the *path* remain supported. Original URL text is still compared **exactly**, not silently normalized or rewritten.

The new shared file `tests/fixtures/fieldshield-url-authority-parity.v1.json` is mirrored byte-for-byte in PhiOS at `phishell/src/security/fixtures/fieldshield-url-authority-parity.v1.json`. The Python tests exercise actual `_normalize` and `scan_observations`. The PhiOS tests exercise actual browser normalization and signature-gated matching, including incomplete coverage for rejected observations.

## Security tradeoff and compatibility

Some previously accepted unusual URLs will now be **rejected** instead of silently interpreted. This intentional change favors matching integrity over broad URL syntax coverage. Rejected observations count as uninspected and yield an INCOMPLETE result. Signed packs containing rejected URLs fail validation. Review source packs for compatibility before using them.

These tests establish agreed behavior **only for listed vectors**, not formal total parity. This is not a live spyware scanner or proof a device is clean. No network, file access privileges, remediation, or trusted publisher keys are added.

Tests: `python -m unittest discover -s tests -v`
