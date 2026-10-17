# FieldShield

**Shield in. Shield out. Ledger above ego.**

FieldShield is an experimental, independently reusable trust-and-safety layer for the Field Lab, Crane Fly, Super Phi Vessel, and other projects. Its first milestone is a **standard-library-only, offline static scanner**. It helps identify risky installer hooks, suspicious command patterns, and potential prompt-injection instructions **before** you install, import, or execute downloaded code.

## Milestone 1: offline inspection

Requires Python 3.10+; no pip install and no third-party dependencies.

```bash
python3 fieldshield.py scan ./untrusted-project
python3 fieldshield.py scan ./untrusted-project --format json
python3 fieldshield.py scan ./untrusted-project --output /tmp/fieldshield-report.json
python3 -m unittest discover -s tests -v
```

**Use a separately downloaded or cloned copy of the project. Do not run `npm install`, `pip install`, or imported project code just to scan it.** Reading an untrusted repository in FieldShield does not run its install scripts.

Decisions:
- **HOLD**: high-severity indicators detected, or scan incomplete. Do not install automatically.
- **REVIEW**: medium-severity signals detected. Human review recommended.
- **PASS**: no configured indicators in the text files that were inspected. **Not** a certificate of safety.

Machine-readable reports include per-file SHA-256 hashes, rule IDs, file paths, line numbers, scan limitations, and a timestamp. Reports intentionally omit matched line content to avoid copying secrets into logs. Explanations identify **observable patterns**, never claim to detect motives or prove malicious intent.

### Scope and limitations

Static indicators are imperfect. Benign documentation, security tests, build automation, and examples can trigger findings. Obfuscated payloads, vulnerabilities, unsafe dependencies, dangerous runtime behavior, binary executables, encodings other than UTF-8, and external network effects may be missed. Symlinks are not traversed. Large, unreadable, and non-text files are reported as uninspected and force a HOLD decision. `.git` internals are explicitly out of scope. Do not treat PASS as permission to execute unknown code.

FieldShield v0.1 does **not** sandbox or execute programs, unpack archives, connect to any online scanner, call a model, block processes, or protect third-party copies of open-source software. Production enforcement requires independent authorization around **actual tool actions**, not just text screening.

## Architecture roadmap

1. **Inspect before trust**: offline source scan, manifest rules, bounded file reading, SHA-256 evidence.
2. **Provenance and quarantine**: signed scan receipts, reproducible policy versions, archive inspection, dependency/secret scanners, safe sandbox integration.
3. **Shield inbound**: prompt-injection threat modeling for retrieved pages, documents, packages and tool output.
4. **Shield outbound**: a separate action-authorization gateway in Crane Fly and Super Phi Vessel with least privilege, scoped capabilities, human review for consequential actions, and tamper-evident decision receipts.
5. **Integration contract**: a small JSON API and language-neutral schema so the protocol is not tied to one AI model.

**Governance:** explanations and appeal paths; no unsupported judgments about people's intentions; fail closed when scanning or authorization fails.

> This is an experimental safety aid, not a malware detector or a guarantee against abuse.
