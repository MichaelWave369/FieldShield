# FieldShield / PhiOS strict JSON contract v3

**Security purpose:** prevent two offline engines interpreting duplicate or
ambiguous JSON evidence, signed IOC packs or trust policies differently.

FieldShield `sentinel._strict_json` now underpins the local pack loader,
the observation reader and the opt-in `sentinel_verified._json` loader for
detached signatures and trust policy. PhiOS uses its own independent
`parseStrictJson` implementation and the same versioned input corpus.

The byte-identical fixtures are:

- FieldShield: `tests/fixtures/fieldshield-strict-json-parity.v1.json`
- PhiOS: `phishell/src/security/fixtures/fieldshield-strict-json-parity.v1.json`

This release locks six valid and 23 malformed/ambiguous JSON cases,
including escaped duplicate keys at nested levels, unusual whitespace,
truncated containers, invalid numeric constants, nonfinite exponent
overflow, integers too large for exact JavaScript representation, leading
UTF-8 BOM, and a 48-level maximum nesting depth.

Some previously accepted documents now deliberately **fail closed**:
duplicate properties, nonstandard numeric constants, numeric overflow,
out-of-range integers and excessive nesting. This is a compatibility
restriction; manually inspect and reissue malformed source documents
instead of ignoring validation errors.

The parser does not authenticate that an IOC publisher is legitimate,
and a valid JSON document is not evidence of a clean host. The existing
Ed25519 trust check, operator consent and security boundaries still apply.
No real IOC feeds, sensitive observations, secret keys, network calls,
background scanning, or remediation are introduced.

For clarity: the independent STIX importer may use its own policy;
this contract specifically protects Sentinel pack/observation ingress and
Verified Pack manifests/trust-store documents.

Run `python -m unittest discover -s tests -v` with Python 3.11 and 3.12.
The golden corpus is a bounded regression contract, not an exhaustive
formal proof of equivalence for all possible JSON inputs.
