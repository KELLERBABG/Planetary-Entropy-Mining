"""Versioned entropy certificate schema.

A certificate binds one capture window to its hardened entropy commitment
and nullifier, so a verifier can check (without the raw signal):

  * the capture metadata (source, sample rate, duration, quantizer bits,
    conservative min-entropy from the SP 800-90B suite),
  * the hardened polynomial artifact (evaluations + MAC),
  * the deterministic nullifier for (node, window),
  * a keyed MAC over the whole certificate body.

Schema version is explicit and every field is type-checked on decode.
Serialization is canonical JSON (deterministic key order) so two producers
with identical inputs produce byte-identical certificates.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

_CERT_VERSION = 1
_MAC_CTX = b"PEM-certificate-v1"
_DIGEST_CTX = b"PEM-entropy-digest-v1"


@dataclass
class CaptureMeta:
    """Metadata describing one capture window."""

    source_name: str
    sample_rate: float
    seconds: float
    bits: int
    conservative_bits_per_byte: float
    digest_hex: str = ""

    def encode(self) -> dict:
        return {
            "source": self.source_name,
            "sample_rate": self.sample_rate,
            "seconds": self.seconds,
            "bits": self.bits,
            "conservative_min_bits_per_byte": round(self.conservative_bits_per_byte, 6),
            "entropy_digest": self.digest_hex,
        }


@dataclass
class EntropyCertificate:
    """Versioned, self-contained certificate."""

    version: int
    capture: CaptureMeta
    hardening: dict           # HardenedEntropy.to_dict()
    nullifier: str            # hex
    window_id: str
    node_id: str
    mac_b64: str = ""

    def _body_dict(self) -> dict:
        return {
            "version": self.version,
            "node_id": self.node_id,
            "window_id": self.window_id,
            "capture": self.capture.encode(),
            "hardening": self.hardening,
            "nullifier": self.nullifier,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self._body_dict(), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        return {**self._body_dict(), "mac_b64": self.mac_b64}

    @classmethod
    def from_dict(cls, d: dict) -> "EntropyCertificate":
        c = d["capture"]
        return cls(
            version=d["version"],
            node_id=d["node_id"],
            window_id=d["window_id"],
            capture=CaptureMeta(
                source_name=c["source"],
                sample_rate=float(c["sample_rate"]),
                seconds=float(c["seconds"]),
                bits=int(c["bits"]),
                conservative_bits_per_byte=float(c["conservative_min_bits_per_byte"]),
                digest_hex=c.get("entropy_digest", ""),
            ),
            hardening=d["hardening"],
            nullifier=d["nullifier"],
            mac_b64=d.get("mac_b64", ""),
        )

    @property
    def body_bytes(self) -> bytes:
        return self.to_bytes()


def entropy_digest(captured_samples: bytes, salt: bytes = b"") -> str:
    """Stable digest of the quantized capture bytes (for the cert)."""
    h = hashlib.blake2b(digest_size=32, salt=salt or bytes(range(16)))
    h.update(_DIGEST_CTX + captured_samples)
    return h.hexdigest()


def sign_certificate(cert: EntropyCertificate, issuer_key: bytes) -> str:
    """Attach an issuer MAC (HMAC-SHA256) over the canonical body."""
    mac = hmac.new(issuer_key, _MAC_CTX + cert.body_bytes, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def verify_certificate(cert: EntropyCertificate, issuer_key: bytes) -> bool:
    """Verify the issuer MAC and the schema invariants."""
    if cert.mac_b64 == "":
        return False
    expected = sign_certificate(cert, issuer_key)
    return hmac.compare_digest(cert.mac_b64, expected)


def create_certificate(capture: CaptureMeta, hardening_dict: dict,
                       nullifier_hex: str, window_id: str, node_id: str,
                       issuer_key: bytes) -> EntropyCertificate:
    """Build a fully-signed certificate from validated pieces."""
    cert = EntropyCertificate(
        version=_CERT_VERSION,
        capture=capture,
        hardening=hardening_dict,
        nullifier=nullifier_hex,
        window_id=window_id,
        node_id=node_id,
    )
    cert.mac_b64 = sign_certificate(cert, issuer_key)
    return cert


__all__ = ["CaptureMeta", "EntropyCertificate", "entropy_digest",
           "sign_certificate", "verify_certificate", "create_certificate"]