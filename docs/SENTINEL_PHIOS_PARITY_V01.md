# FieldShield ↔ PhiOS observation parity: golden contract v1

Two separate, local-first runtimes can only agree when they share an explicit
behavioral contract. This milestone adds **synthetic, source-controlled**
test vectors to both FieldShield's Python Sentinel and the PhiOS PhiShell
browser evidence matcher.

The canonical v1 vector set in this repository is:
`tests/fixtures/fieldshield-observation-parity.v1.json`. PhiOS includes the
byte-for-byte matching fixture at:
`phishell/src/security/fixtures/fieldshield-observation-parity.v1.json`.

The vectors lock expected decisions, inspected/uninspected counts, and
ordered exact finding triples: indicator ID, kind and observation index.
Cases include every supported observation kind, URL-hostname domain fallback,
exact near-miss behavior, invalid/partially inspected evidence, empty scope,
trailing-domain-dot normalization and privacy-sensitive URL query data.

FieldShield's reference test runs **the actual** `sentinel.load_pack_bytes`
and `sentinel.scan_observations` Python functions. The PhiOS companion
test separately creates an ephemeral Ed25519 key, signs the exact fixture
pack bytes using WebCrypto, verifies the signature and caller-supplied pin,
then matches observations and compares the same result projection.

Commands:

    python -m unittest discover -s tests -v

No real spyware indicators, private evidence, signing secrets, network
access or device scans are included. The results do not attest infection
or a clean host.

**Scope limitation:** This tests defined golden vectors; it is not a
mathematical or exhaustive proof that Python `urllib.parse.urlsplit`
and browser `URL` behave identically for every malformed or exotic URL.
Do not silently expand normalization behavior without adding parity
vectors and checking the documented difference. Any change to the fixture
must be coordinated in both repos, with both CI suites green.
