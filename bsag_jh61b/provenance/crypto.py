from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .content import CERT_FIELDS, MANIFEST_FIELDS, hex_string
from .types import VerificationContext, VerificationUnavailable


def verifies(key: str, signature: str, value: dict[str, Any]) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature), rfc8785.dumps(value))
    except (InvalidSignature, ValueError):
        return False
    return True


def manifest_signatures(value: dict[str, Any], root_key: str) -> list[str]:
    cert = value["course_cert"]
    failures = []
    if not verifies(root_key, cert["root_sig"], {k: cert[k] for k in CERT_FIELDS}):
        failures.append("course certificate root signature")
    if not verifies(cert["course_pubkey"], value["sig"], {k: value[k] for k in MANIFEST_FIELDS}):
        failures.append("activation manifest course signature")
    return failures


@dataclass
class Signatures:
    failures: list[tuple[str, str]] = field(default_factory=list)
    seals: set[str] = field(default_factory=set)


def verify_signatures(context: VerificationContext) -> Signatures:
    if not hex_string(context.root_public_key, 64):
        msg = "A staff-configured root_public_key (64 lowercase hex characters) is required"
        raise VerificationUnavailable(msg)
    content = context.content
    result = Signatures()
    manifests = [] if content.manifest is None else [("provenance-manifest", content.manifest)]
    manifests.extend((s.name, s.start["manifest"]) for s in content.sessions)
    for name, manifest in manifests:
        result.failures.extend((name, failure) for failure in manifest_signatures(manifest, context.root_public_key))
    for session in content.sessions_with_metadata:
        for cp in session.meta["checkpoints"]:
            if not verifies(session.public_key, cp["sig"], {"seq": cp["seq"], "hash": cp["hash"]}):
                result.failures.append((session.name + ".meta", f"checkpoint signature at seq {cp['seq']}"))
    for seal in content.seals:
        if seal.rolling_id is not None:
            candidates = [s for s in content.sessions_with_metadata if s.id == seal.rolling_id]
        else:
            candidates = list(reversed(content.sessions_with_metadata))
        if not candidates:
            continue
        if seal.rolling_id is not None and len(candidates) != 1:
            continue
        if any(verifies(s.public_key, seal.signature, seal.value) for s in candidates):
            result.seals.add(seal.name)
        else:
            result.failures.append((seal.name, "recording seal signature"))
    return result
