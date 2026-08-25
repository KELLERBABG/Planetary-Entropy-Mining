"""Reed-Solomon erasure coding over GF(256)."""

from .reedsolomon import Shard, encode, decode

__all__ = ["Shard", "encode", "decode"]