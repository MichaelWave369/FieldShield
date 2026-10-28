# Φ Sentinel v0.2: STIX Intelligence Bridge

**Experimental, offline, source-attributed importer.** This is a strict
subset of STIX 2.1, **not** an interpreter for arbitrary STIX patterns or an
automatic feed downloader. The importer is separate from the scanning engine:
it converts a *locally reviewed* `.stix2`/JSON bundle into a JSON pack that
Sentinel v0.1 already understands.

## Example

Use an existing, local, consentfully obtained STIX 2.1 JSON bundle.
From the repository root:

    python sentinel_stix.py ./reviewed.stix2 \
      --source "Reviewed research publication" \
      --reference "https://example.org/research" \
      --output ./reviewed-pack.json

Then use existing Sentinel on a local evidence collection:

    python sentinel.py observations ./observations.json --iocs ./reviewed-pack.json

With no `--output`, the importer prints JSON to stdout and creates no report.
When supplied, output uses exclusive creation and will not overwrite an
existing file. No automatic network, privilege escalation, file execution,
phone connection, secret collection, or telemetry is performed.

## Exact supported pattern subset

- `[domain-name:value = 'host.example.invalid']` -> `domain`
- `[url:value = 'https://host.example.invalid/path']` -> `url`
- `[file:hashes.'SHA-256' = '<64 hex characters>']` -> `sha256`
- `[process:name = 'example-process']` -> `process`
- `[app:id = 'org.example.synthetic']` -> `bundle_id` (MVT extension)

Only **one literal equality condition in one observation expression** is
supported. Literal quoting uses apostrophes without backslash escapes.
No OR, AND, FOLLOWEDBY, REPEATS, WITHIN, START/STOP, MATCHES, LIKE,
subobject traversal, wildcards, IP ranges, or general STIX expressions.
Unsupported **active** indicators cause the **entire conversion to fail**
rather than pretending a subset is complete.

All imported indicator objects must explicitly declare `spec_version: 2.1`
and `pattern_type: stix`; if supplied, `pattern_version` must be `2.1`.
A timestamped `valid_from` is required. Revoked, expired, and not-yet-active
indicators are **not** imported, and counts are recorded in `origin_stix`.
If nothing remains, the importer fails. Duplicate indicator IDs are rejected
instead of silently choosing a version.

STIX `confidence` 0-39 maps to `low`, 40-79 to `medium`, and 80-100 to
`high`; missing scores map conservatively to `low`. These values reflect
source-provided confidence, **not** independently verified risk or probability
of infection.

A SHA-256 digest of the local source bundle, source label, input URL, and
conversion scope are recorded for provenance. Neither the input bundle
nor the reference URL is independently verified. The importer does not validate
signatures, TLP markings, license rights, publisher reputation, or freshness
beyond the STIX validity fields. A local attacker can forge unsigned packs.
Before operational use, **independently verify source, authenticity, license
and sharing restrictions**. Only import data you are authorized to use.

## Testing and limitations

    python -m unittest discover -s tests -v

- Entire inputs are bounded at 8 MB / 20,000 STIX objects.
- Inputs must be local, regular, non-symlink files; don't read concurrently
  changing untrusted filesystem paths.
- Packs remain read-only input to Sentinel; no automatic remediation.
- Existing Sentinel path/URL matching semantics remain deliberately narrow.
- The source must be reviewed before use; the synthetic examples in
  `rules/` are **not live surveillance intelligence**.
- A match is not proof of compromise. A missing match is not proof of safety.

## Next gates

1. Formal parser / typed AST if full STIX expression semantics are needed.
2. Trust-store, signed-pack verification, publisher allowlists and license/TLP handling.
3. Independent validation with known clean and positive forensic fixtures.
4. Consent-based MVT evidence import, then optional PhiOS Security Center UI.

### References

- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- Amnesty MVT IOCs: https://docs.mvt.re/en/stable/iocs/
