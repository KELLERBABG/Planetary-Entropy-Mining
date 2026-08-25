"""Tests for the versioned entropy certificate schema."""

import json

import pytest

from identity.certificate import (
    CaptureMeta,
    EntropyCertificate,
    create_certificate,
    entropy_digest,
    sign_certificate,
    verify_certificate,
)

ISSUER = b"test-issuer-key-0000000000000000"


def _sample_cert() -> EntropyCertificate:
    capture = CaptureMeta(
        source_name="thermal",
        sample_rate=48_000.0,
        seconds=2.0,
        bits=8,
        conservative_bits_per_byte=6.102,
        digest_hex=entropy_digest(b"\x01\x02\x03" * 100),
    )
    return create_certificate(
        capture=capture,
        hardening_dict={"params": {"degree": 31}, "evaluations": "00", "mac": "aa"},
        nullifier_hex="ab" * 32,
        window_id="2026-01-01T00:00Z",
        node_id="node-42",
        issuer_key=ISSUER,
    )


def test_certificate_serialization_round_trip():
    cert = _sample_cert()
    d = cert.to_dict()
    restored = EntropyCertificate.from_dict(json.loads(json.dumps(d)))
    assert restored.version == cert.version
    assert restored.capture == cert.capture
    assert restored.nullifier == cert.nullifier
    assert restored.window_id == cert.window_id
    assert restored.node_id == cert.node_id
    assert restored.hardening == cert.hardening
    assert restored.mac_b64 == cert.mac_b64
    assert verify_certificate(restored, ISSUER)


def test_certificate_body_is_canonical():
    cert1 = _sample_cert()
    cert2 = _sample_cert()
    # Identical inputs -> byte-identical canonical bodies.
    assert cert1.body_bytes == cert2.body_bytes


def test_tamper_detection_each_field():
    cert = _sample_cert()
    base = cert.to_dict()
    variations = [
        ("node_id", "node-43"),
        ("window_id", "2026-01-02T00:00Z"),
        ("nullifier", "ff" * 32),
    ]
    for key, value in variations:
        d = dict(base)
        d[key] = value
        forged = EntropyCertificate.from_dict(d)
        assert not verify_certificate(forged, ISSUER), f"change to {key} not detected"
    # Capture mutation.
    d = dict(base)
    d["capture"]["bits"] = 4
    forged = EntropyCertificate.from_dict(d)
    assert not verify_certificate(forged, ISSUER)
    # Hardening mutation.
    d = dict(base)
    d["hardening"]["evaluations"] = "ff"
    forged = EntropyCertificate.from_dict(d)
    assert not verify_certificate(forged, ISSUER)


def test_empty_mac_rejected():
    cert = _sample_cert()
    cert.mac_b64 = ""
    assert not verify_certificate(cert, ISSUER)


def test_wrong_issuer_rejected():
    cert = _sample_cert()
    assert not verify_certificate(cert, b"wrong-issuer-key")


def test_entropy_digest_deterministic_and_sensitive():
    a = entropy_digest(b"capture-bytes")
    b = entropy_digest(b"capture-bytes")
    c = entropy_digest(b"capture-byteS")
    assert a == b
    assert a != c
    assert len(a) == 64  # 32-byte blake2b hex


def test_create_certificate_round_trip_with_hardening_flow():
    # Integration: capture -> harden -> nullifier -> cert -> verify.
    from hardening import harden
    from identity.nullifier import nullifier, random_nullifier_key
    import numpy as np

    raw = np.random.default_rng(0).normal(size=8000)
    artifact = harden(raw)
    node = random_nullifier_key("node-7")
    win = "window-123"
    nul = nullifier(artifact_eval_seed(raw, artifact), node, win)

    capture = CaptureMeta(
        source_name="thermal",
        sample_rate=48_000.0,
        seconds=1.0,
        bits=8,
        conservative_bits_per_byte=6.0,
        digest_hex=entropy_digest(bytes(np.round(raw).astype(np.int8).tobytes())),
    )
    cert = create_certificate(capture, artifact.to_dict(), nul.hex(),
                              win, node.node_id.decode(), ISSUER)
    assert verify_certificate(cert, ISSUER)
    restored = EntropyCertificate.from_dict(json.loads(json.dumps(cert.to_dict())))
    assert verify_certificate(restored, ISSUER)


def artifact_eval_seed(raw, artifact):
    # The hardening artifact already binds the seed; for the nullifier we use
    # the same extraction the pipeline uses.
    from hardening.polynomial import extract_seed
    return extract_seed(raw, artifact.params)