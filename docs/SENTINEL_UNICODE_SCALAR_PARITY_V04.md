# FieldShield ↔ PhiOS Unicode scalar JSON parity v4

**Security boundary:** Only valid Unicode scalar strings may appear in
operator-provided IOC packs, detached signatures, trust policies or
observation files. Python's `json.loads` normally accepts isolated
`\\ud800`–`\\udfff` escape sequences, while JavaScript's UTF-8
TextEncoder silently substitutes U+FFFD when asked to encode such a
string. That can change byte identity and cause divergent interpretation.

FieldShield's `sentinel._strict_json` now checks every decoded JSON
object key and string value, including nested arrays. Lone high or low
surrogates are rejected, not repaired. Correctly paired escapes such as
`\\ud83d\\ude00` are accepted as Unicode scalar values. The
`sentinel_verified._json` manifest/trust reader shares this gate.

The exact synthetic fixture is mirrored in two repos:

- FieldShield: `tests/fixtures/fieldshield-unicode-scalar-parity.v1.json`
- PhiOS: `phishell/src/security/fixtures/fieldshield-unicode-scalar-parity.v1.json`

It defines **7 accepted and 12 rejected cases**, including embedded,
nested, escaped and key-position surrogates, plus correct pairs and
literal escape-sequence strings. Each runtime executes its own actual
parser against these vectors. Additional integration tests exercise
actual pack, manifest and observation input boundaries.

This is intentionally a compatibility restriction. Previously accepted
malformed Unicode inputs fail closed. The operator should correct
or reissue such evidence, not automatically substitute characters.

Scope remains offline and operator-controlled. No network requests,
host scans, remediation or additional trust grants occur.
Valid parsing never means a publisher, IOC or device is trustworthy.
This corpus is regression coverage, not formal universal parser parity.

Verify: `python -m unittest discover -s tests -v` under Python
3.11 and 3.12; co-review PhiOS's companion PR before merging.
