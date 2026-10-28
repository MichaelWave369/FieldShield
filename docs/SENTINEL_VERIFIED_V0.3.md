# Φ Sentinel v0.3: Verified Intelligence Packs

**Offline, explicit-trust cryptographic authenticity.** An optional verification
layer authenticates a local IOC pack before the existing Sentinel engine scans
any evidence. The legacy standard-library-only scanner remains available and
is **unsigned by design**. Use `sentinel_verified.py scan` for a signature-
required workflow that never silently falls back to an unsigned pack.

## What this does and does not establish

- Cryptographically checks the **exact pack bytes** against a detached Ed25519
  signature and manually installed trust-store public key.
- Requires a pinned publisher/key ID. Unknown publishers and keys fail closed.
- Refuses altered signatures and pack digests, future-issued/expired signatures,
  locally revoked keys and pack digests, and packs before a local issuance floor.
- Includes a SHA-256 receipt of the exact signed pack, manifest, trust policy,
  and public key fingerprint in verified scan reports.
- Performs **no automatic downloads, network access, execution or upload**.
- **Does not establish publisher honesty, IOC quality, device safety,
  the trust-store's authenticity, signature timestamp authority, or anti-
  rollback against a trusted key signing newer malicious material.**
- No trust anchors are shipped: the example trust store is intentionally EMPTY.
- A signed pack is only authentic to a locally trusted key. It is NOT inherently
  genuine spyware intelligence, and signature verification is NOT a malware scan.

The older `sentinel.py` and `sentinel_stix.py` use only Python's standard
library. Verified mode requires the independently audited **cryptography**
dependency (pinned in `requirements-verified.txt`).

## Optional installation (Python 3.11+ recommended)

    python -m pip install -r requirements-verified.txt

Review the lock/pinned dependency yourself for deployment, and use an offline
wheelhouse for air-gapped PhiOS/PhiArk systems. Pip installation may require
the internet; **running verified scans does not**.

## Using verified mode

You need three separate locally reviewed inputs:
1. `pack.json`: a Sentinel v0.1 IOC pack, possibly produced by the strict
   v0.2 STIX importer.
2. `pack.sig.json`: an Ed25519 detached manifest authorizing the digest of
   those EXACT pack bytes, signed with the publisher's offline key.
3. `trusted.json`: a locally created and **manually trusted** publisher policy
   containing the corresponding Ed25519 public key (base64 raw 32 bytes).

Verify without scanning:

    python sentinel_verified.py verify --pack ./pack.json \
      --signature ./pack.sig.json --trust ./trusted.json

Scan user-consented, already collected evidence:

    python sentinel_verified.py scan --pack ./pack.json \
      --signature ./pack.sig.json --trust ./trusted.json \
      observations ./observations.json

The other supported scan mode is `files ./folder`, which matches only
SHA-256 file digests and exact relative paths. Scan reports are printed as
JSON to stdout. Use shell redirection only when you explicitly want a report
saved. Exit 0 = no matches in inspected scope, 1 = indicators found, 2 =
incomplete or verification failure. **Exit 0 does not mean uninfected.**

## Trust-store format

This example includes a placeholder key. Replace it with the publisher's
**out-of-band verified** public key. Never trust a key merely because the
same downloaded archive provides both the trust policy and signed IOC pack.

    {
      "schema": "fieldshield.trust-store.v1",
      "publishers": [{
        "id": "reviewed-lab",
        "keys": [{
          "id": "signing-2026-1",
          "algorithm": "ed25519",
          "state": "trusted",
          "public_key_b64": "BASE64_OF_32_BYTE_PUBLIC_KEY"
        }],
        "blocked_pack_sha256": [],
        "minimum_issued_at": "2026-01-01T00:00:00Z"
      }]
    }

To revoke a key, set `state` to `revoked`. To revoke a known IOC pack,
place the exact lower-case SHA-256 in `blocked_pack_sha256`. To disallow
older signatures, advance `minimum_issued_at`. All these changes are
manual and require proper local trust-store maintenance and backup.

**Important:** The minimum issuance date and blocklist are only as trustworthy
as the local file. A caller who can replace the trust store can bypass them.
v0.3 does not distribute revocation updates or establish secure time.

## Author-side signing (offline)

Keep the Ed25519 PEM private key **outside the repo** and out of all backups
that are not encrypted. On a trusted machine with OpenSSL:

    openssl genpkey -algorithm Ed25519 -out private-signing.pem

Restrict file access before use (`chmod 600 private-signing.pem` on POSIX).
**Never check in this private key.** Windows uses filesystem ACLs instead of
POSIX `chmod`. The signer accepts only unencrypted PKCS8 Ed25519 PEM keys,
and does not generate or store keys itself.

    python sentinel_verified.py sign --pack ./pack.json \
      --private-key ./private-signing.pem \
      --publisher reviewed-lab --key-id signing-2026-1 \
      --expires-at 2026-12-01T00:00:00Z \
      --output ./pack.sig.json

`--output` creates a NEW file only and refuses overwriting. Without it, the
manifest is printed to stdout. Operator should keep the signing key away from
workstations used to inspect potentially hostile evidence.

To export the corresponding raw 32-byte Ed25519 public key as base64, use
the `cryptography` package securely offline. Example:

    python -c "import base64; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; k=serialization.load_pem_private_key(open('private-signing.pem','rb').read(),password=None); print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())"

Copy the base64 output into a locally reviewed trust store **only after
independently verifying the key fingerprint or another authenticated channel**.
The publisher ID and key ID must exactly match the signed manifest.

## Security constraints and roadmap

- All inputs are bounded and reject symlinks where supported; sources are
  read once to prevent signing/verification of different pack snapshots.
- Detached manifests authenticate their entire metadata, including publisher,
  key ID, exact digest, issue/expiry timestamps, with domain separation.
- Unsupported signature algorithms, malformed inputs, duplicate JSON keys,
  expired manifests, untrusted keys and known local blocks fail closed.
- This is a prototype, not a complete software supply-chain trust framework.
  Directory swaps and filesystem races require further platform-specific
  hardening before hostile multi-user deployment.
- The signing timestamp is asserted by the publisher, **not** a trusted
  timestamp authority. A compromised trusted key can still sign false claims.
- Future: signed trust-store distribution, secure key rotation, transparency
  log/monotonic release counters, TLP/license metadata, provenance review,
  independent cryptographic review, and PhiArk offline bundle integration.

**All test intelligence is synthetic. No active spyware indicators are bundled.**
