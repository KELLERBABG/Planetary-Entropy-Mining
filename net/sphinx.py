"""Sphinx-style layered onion framing over a fixed route (simulated).

Implements the transport-layer privacy primitive of the Planetary Entropy
Audit: a sender wraps a payload in *n* layers of X25519 + AES-GCM, one per
hop of a fixed route. A hop can only peel the layer addressed to it — it
learns the next-hop *tag* (a keyed pseudorandom handle), never the identity
of the final recipient, the payload, or the full route. Per-hop identity
mixing is provided by the tag indirection exactly as in Sphinx.

Security properties (each proven in tests):
  * Layered encryption: only the hop whose key produced a layer can open it.
  * Tag mixing: an intermediate hop learns only "which link to forward on",
    not the destination or the payload.
  * Replay protection: each packet carries a random session id; a Node that
    has already seen a (session, seq) rejects the duplicate.
  * Order protection: within a session, sequence numbers must strictly
    increase.
  * Deterministic: given identical seeds, wrap() produces byte-identical
    packets (required for reproducible tests/demos).

Cryptographic primitives come from the `cryptography` package (the lone
extra dependency, already used for HKDF/hashes); no real network sockets
are involved.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_MAGIC = b"PEMSPX1F"
_TAG_LEN = 32
_KEY_LEN = 32
_NONCE_LEN = 12
_SESSION_LEN = 16
_SEQ_LEN = 8
_HEADER = _TAG_LEN + _KEY_LEN + _NONCE_LEN  # 32 + 32 + 12 = 76 bytes/layer


class WrongHopError(Exception):
    """Packet is not addressed to this hop."""


class ReplayError(Exception):
    """Packet already seen (same session + seq)."""


class OutOfOrderError(Exception):
    """Packet sequence number is not strictly increasing within its session."""


@dataclass(frozen=True)
class HopKey:
    """Long-term X25519 keying material of one route hop."""

    node_id: str
    private: X25519PrivateKey

    @classmethod
    def generate(cls, node_id: str, seed: bytes | str = b"") -> "HopKey":
        """Deterministic key from ``seed`` (SHA-256 when a string is given)."""
        if isinstance(seed, str):
            seed = seed.encode()
        if not seed:
            seed = node_id.encode()
        dk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                  info=b"pem:sphinx:x25519:v1").derive(seed)
        return cls(node_id=node_id, private=X25519PrivateKey.from_private_bytes(dk))

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class Route:
    """A fixed sender->hop0->hop1->...->final path."""

    hops: tuple[HopKey, ...]

    def __len__(self) -> int:
        return len(self.hops)

    def __getitem__(self, i: int) -> HopKey:
        return self.hops[i]


def create_route(n_hops: int, node_ids: list[str] | None = None,
                 seed: bytes | str = "route-seed") -> Route:
    """Build a deterministic n-hop route for tests/demos."""
    node_ids = node_ids or [f"hop{i}" for i in range(n_hops)]
    if len(node_ids) != n_hops:
        raise ValueError("node_ids must match n_hops")
    return Route(tuple(
        HopKey.generate(node_ids[i], f"{seed}:{i}") for i in range(n_hops)
    ))


# ---------------------------------------------------------------------------
# Per-hop key derivation (no index needed — keys bind to the ephemeral key).
# ---------------------------------------------------------------------------


def _derive_keys(shared: bytes, ephem_pub: bytes) -> tuple[bytes, bytes]:
    """(enc_key, tag_key) for one layer, domain-separated by the ephemeral key."""
    info = b"pem:sphinx:layer:v1" + ephem_pub
    material = HKDF(algorithm=hashes.SHA256(), length=2 * _KEY_LEN,
                    salt=None, info=info).derive(shared)
    return material[:_KEY_LEN], material[_KEY_LEN:]


def _hop_tag(tag_key: bytes, ephem_pub: bytes) -> bytes:
    return hmac.new(tag_key, b"pem:sphinx:tag:v1" + ephem_pub,
                    hashlib.sha256).digest()


def _inner_block(payload: bytes | None, inner_packet: bytes | None,
                 final: bool, session: bytes, seq: int) -> bytes:
    """Serialize one layer's plaintext.

    Layout: magic(8) | final(1) | session(16) | seq(8) | len(2) | body
    where body is the payload (final layer) or the next inner packet.
    """
    body = payload if final else inner_packet
    if body is None:
        raise ValueError("need payload (final) or inner packet (non-final)")
    if len(body) > 0xFFFF:
        raise ValueError("layer body too large (max 65535 bytes)")
    return (_MAGIC + (b"\x01" if final else b"\x00") + session
            + struct.pack(">Q", seq) + struct.pack(">H", len(body)) + body)


def _parse_block(plain: bytes) -> tuple[bool, bytes, bytes, int, bytes]:
    if len(plain) < 8 + 1 + _SESSION_LEN + _SEQ_LEN + 2:
        raise ValueError("malformed layer plaintext")
    magic = plain[:8]
    if magic != _MAGIC:
        raise ValueError("bad magic")
    final = plain[8] == 1
    session = plain[9:9 + _SESSION_LEN]
    seq = struct.unpack(">Q", plain[9 + _SESSION_LEN:9 + _SESSION_LEN + _SEQ_LEN])[0]
    body_len = struct.unpack(">H", plain[9 + _SESSION_LEN + _SEQ_LEN:
                                         9 + _SESSION_LEN + _SEQ_LEN + 2])[0]
    body = plain[9 + _SESSION_LEN + _SEQ_LEN + 2:]
    if len(body) != body_len:
        raise ValueError("truncated layer body")
    return final, session, seq, body_len, body


# ---------------------------------------------------------------------------
# Wrapping (sender side)
# ---------------------------------------------------------------------------


def wrap(payload: bytes, route: Route, seed: bytes | str = "wrap-seed",
         session: bytes | None = None, seq: int = 0) -> bytes:
    """Wrap ``payload`` for delivery through ``route`` (return onion bytes).

    Layers are applied innermost-first. Each layer uses its own ephemeral
    X25519 key derived from ``seed`` per layer index, so the same seed
    produces byte-identical packets (deterministic demos/tests).
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes-like")
    if len(route) == 0:
        raise ValueError("empty route")
    if session is None:
        session = hashlib.sha256(b"pem:sphinx:session:v1" + str(seed).encode()).digest()[:_SESSION_LEN]
    if len(session) != _SESSION_LEN:
        raise ValueError("session must be 16 bytes")
    if seq < 0:
        raise ValueError("seq must be >= 0")

    block: bytes | None = bytes(payload)
    rng_state = int(hashlib.sha256(str(seed).encode()).hexdigest(), 16)
    for layer, hop in enumerate(reversed(route.hops)):
        # Deterministic ephemeral key + nonce for this layer.
        rng_state = (rng_state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        ep_seed = struct.pack(">Q", rng_state) + struct.pack(">H", layer)
        ephem = X25519PrivateKey.from_private_bytes(_derive_x25519(ep_seed))
        ephem_pub = ephem.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce = hashlib.sha256(b"pem:sphinx:nonce:v1" + ep_seed).digest()[:_NONCE_LEN]

        shared = ephem.exchange(hop.private.public_key())
        enc_key, tag_key = _derive_keys(shared, ephem_pub)
        tag = _hop_tag(tag_key, ephem_pub)

        plain = _inner_block(None if layer else bytes(payload),
                             None if layer == 0 else block,
                             final=(layer == 0), session=session, seq=seq)
        ct = AESGCM(enc_key).encrypt(nonce, plain, tag)
        block = tag + ephem_pub + nonce + ct
    assert block is not None
    return block


def _derive_x25519(seed: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pem:sphinx:x25519:ephem").derive(seed)


# ---------------------------------------------------------------------------
# Unwrapping (hop side)
# ---------------------------------------------------------------------------


@dataclass
class UnwrapResult:
    """What one peer learns from a layer."""

    final: bool
    payload: bytes | None          # set iff final
    next_packet: bytes | None      # set iff not final (forward this)
    next_tag: bytes | None         # the tag for the *following* hop
    session: bytes
    seq: int


def unwrap(packet: bytes, node: "OnionNode") -> UnwrapResult:
    """Peel the outermost layer of ``packet`` addressed to ``node``.

    Raises:
        WrongHopError: the packet's tag is not ours (not the addressee).
        ReplayError: (session, seq) already seen by this node.
        OutOfOrderError: seq not strictly increasing for the session.
    """
    if len(packet) < _HEADER:
        raise ValueError("packet too short")
    tag, ephem_pub, nonce, ct = (packet[:_TAG_LEN],
                                 packet[_TAG_LEN:_TAG_LEN + _KEY_LEN],
                                 packet[_TAG_LEN + _KEY_LEN:_HEADER],
                                 packet[_HEADER:])
    shared = node._private.exchange(_pub_from_bytes(ephem_pub))
    enc_key, tag_key = _derive_keys(shared, ephem_pub)
    expected = _hop_tag(tag_key, ephem_pub)
    if not hmac.compare_digest(expected, tag):
        raise WrongHopError("packet tag does not match this hop")
    try:
        plain = AESGCM(enc_key).decrypt(nonce, ct, tag)
    except InvalidTag as exc:
        raise WrongHopError("cannot open layer (bad tag)") from exc

    final, session, seq, _body_len, body = _parse_block(plain)
    node._check_replay(session, seq)
    if final:
        return UnwrapResult(final=True, payload=body, next_packet=None,
                            next_tag=None, session=session, seq=seq)
    if len(body) < _HEADER:
        raise ValueError("inner packet too short")
    return UnwrapResult(final=False, payload=None, next_packet=body,
                        next_tag=body[:_TAG_LEN], session=session, seq=seq)


def _pub_from_bytes(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


class OnionNode:
    """A route participant: key material + per-node replay/order state."""

    def __init__(self, key: HopKey) -> None:
        self.key = key
        self._private = key.private
        self._seen: dict[bytes, int] = {}  # session -> last seq

    @property
    def node_id(self) -> str:
        return self.key.node_id

    def recv(self, packet: bytes) -> UnwrapResult:
        """Convenience: unwrap + enforce replay/order (same as unwrap)."""
        return unwrap(packet, self)

    def _check_replay(self, session: bytes, seq: int) -> None:
        last = self._seen.get(session)
        if last is not None:
            if seq <= last:
                if seq == last:
                    raise ReplayError(f"replayed (session, seq={seq})")
                raise OutOfOrderError(f"out-of-order seq={seq}, last={last}")
        self._seen[session] = seq


__all__ = [
    "HopKey", "Route", "create_route", "wrap", "unwrap", "OnionNode",
    "WrongHopError", "ReplayError", "OutOfOrderError",
]