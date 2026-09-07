# Provenance integrity checker

## Files

| File | Purpose |
| --- | --- |
| `step.py` | BSAG configuration, trusted inputs, student/staff reporting, and halt/fail-open behavior. |
| `verify.py` | Registers available flags and runs the selected checks. |
| `types.py` | Shared verification context, findings, and report types. |
| `io.py` | Reads submission files safely and inspects filesystem object types. |
| `structure.py` | Implements the three structure-only flags. |
| `content.py` | Parses manifests, logs, metadata, and seals; validates required integrity fields. |
| `crypto.py` | Verifies Ed25519 signatures and caches signature verdicts. |
| `integrity.py` | Implements the five content flags below. |

## Flags

| Flag | Detects |
| --- | --- |
| `invalid_structure` | Invalid filesystem types, including directories where files belong, links, and special files. |
| `missing_files` | Missing activation manifest, recording directory, required log/meta or seal/signature pairs. |
| `unexpected_file` | Unrecognized filenames inside `.provenance`. |
| `invalid_content` | Malformed JSON or invalid required integrity fields and encodings. |
| `hash_chain_invalid` | Incorrect event hashes, broken previous-hash links, or sequence gaps. |
| `invalid_signature` | Invalid course-certificate, activation-manifest, recording-seal, or checkpoint signatures; excludes enrollment signatures. |
| `recording_binding_mismatch` | Wrong course/semester/assignment or inconsistent session IDs, keys, and seal associations. |
| `log_bytes_mismatch` | Log or metadata bytes contradict a verified seal; growing recordings allow signed prefixes. |

Only selected flags run. Findings halt grading by default; operational errors follow `fail_open`.
