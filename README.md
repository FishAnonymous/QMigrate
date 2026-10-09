# Q_Migrate

Paper: **Q-Migrate: Impact-Aware Program Transformation for Post-Quantum Cryptography Migration**

Cryptographic-use extraction for Python, Java and Go, context graphs, migration planning and guarded template transformations. Supported sign/verify units execute through an OpenSSL ML-DSA-65 adapter.

## Files

| Item | Definition |
|---|---|
| qmigrate.py | Extraction, planning, whole-template matching and transformation |
| crypto_adapter.py | OpenSSL key generation, signing and verification |
| migrate.py | Single-file analysis and patch entry point |
| run.py | Controlled tasks and cryptographic validation |
| fixture_templates.py | Supported complete sign/verify templates |

## Environment and execution

Python 3.11 or newer is required. Dependency constraints are listed in `requirements.txt`. Versions used for validation are recorded in `requirements-tested.txt`.

```text
python -m pip install -r requirements.txt
python run.py --bench 30
python run_tests.py
python crypto_adapter.py --selftest
```

The Windows x64 package includes OpenSSL 3.5.5. The program locates `runtime/windows/openssl.exe` automatically. On other systems, use `--openssl` to select an executable.

Java tasks require JDK 17+ with `javac` and `java`; Go tasks require `go`. Compilers are located through PATH. `QMIGRATE_PYTHON` and `QMIGRATE_OPENSSL` select the subprocess interpreter and cryptographic executable.

## Parameters and methods

| Item | Definition |
|---|---|
| Python front end | AST and import-alias resolution |
| Java/Go front ends | Import-supported syntactic matching |
| Graph edges | file-context-indicator with resolved=false |
| Transformation guard | Complete Python AST match or comment-stripped normalized source match |
| Tasks | 18 supported cases and 6 external-verifier policy blockers |
| Detection fixtures | 90 direct-use template variants |
| Cryptographic checks | Valid signature, modified message, wrong key, corrupted signature and key serialization |
| Timing | RSA, EC and ML-DSA; configurable 30 repetitions per algorithm, including subprocess and file I/O |

A template mismatch, unresolved external-verifier compatibility or unavailable ML-DSA-65 provider returns abstain. Generated files and patches are written to a separate directory. Build status is saved per task. Missing compilers produce toolchain_unavailable.

## Implementation scope and data

Automatic transformations cover the packaged complete sign/verify templates and their message/key-size variants. Java and Go use a Python subprocess adapter. Full cross-file CUG analysis, automatic KEM flow transformation, hybrid-protocol synthesis, PKI/TLS migration, staged compatibility implementations and the paper's GitHub sample are not included.

The implementation basis is the paper PDF. Examples and controlled benchmarks are produced by the included generators. PDF page counts, SHA-256 values and experimental-provenance flags are recorded in `provenance.json`.

## Outputs and validation records

results/summary.json, results/tasks and results/toolchains.json.

`results/test_log.txt` contains the test log. `results/verification.json` records the test count, exit status and Python version. `results/source_format.json` records code-comment and docstring counts. `CHECKSUMS.sha256` lists file hashes.
