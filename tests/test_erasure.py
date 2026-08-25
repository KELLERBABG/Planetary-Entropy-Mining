"""Tests for Reed-Solomon erasure coding (erasure/)."""

import pytest

from erasure import Shard, decode, encode

# ---------------------------------------------------------------------------
# Round-trips and the "any k of n" property
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k,n", [(2, 4), (3, 5), (4, 6), (8, 12), (16, 32)])
def test_encode_decode_round_trip(k, n):
    data = bytes(range(256)) * 3 + b"planetary entropy"
    shards = encode(data, k, n)
    assert len(shards) == n
    assert decode(shards, k, n) == data


def test_any_k_shards_reconstruct_full_scan():
    data = (b"entropy certificate sharding test " * 20) + b"\x00\x00trailing"
    k, n = 4, 8
    shards = encode(data, k, n)
    # Every subset of exactly k shards must reconstruct the message.
    from itertools import combinations

    for combo in combinations(shards, k):
        assert decode(list(combo), k, n) == data
    # More than k also works.
    assert decode(list(shards[: k + 1]), k, n) == data
    assert decode(list(shards[k:]), k, n) == data  # parity-only subset


def test_systematic_shards_are_raw_blocks():
    data = bytes(range(48))  # 3 blocks of 16
    k, n = 3, 5
    shards = encode(data, k, n)
    block_len = 16 + 4  # 4-byte length header
    assert len(shards[0].data) == block_len
    assert shards[0].data[4:] == data[:16]
    assert shards[1].data[4:] == data[16:32]
    assert shards[2].data[4:] == data[32:48]
    # Parity shards differ.
    assert shards[3].data != shards[0].data
    assert shards[4].data != shards[1].data


def test_empty_and_small_payloads():
    assert decode(encode(b"", k=2, n=4), k=2, n=4) == b""
    assert decode(encode(b"x", k=3, n=5), k=3, n=5) == b"x"
    assert decode(encode(b"\x00\x00", k=2, n=2), k=2, n=2) == b"\x00\x00"


def test_corrupt_shard_fails_or_recovers():
    """Corrupted parity shards must not break reconstruction..."""
    data = bytes(range(200))
    k, n = 5, 9
    shards = encode(data, k, n)
    # A subset not containing the corrupted shard reconstructs fine.
    bad = bytearray(shards[7].data)
    bad[8] ^= 0xFF
    good = [shards[i] for i in range(9) if i != 7]
    assert decode(good, k, n) == data
    # ...but including the corrupted shard yields garbage or an error,
    # never silent success (no error correction implemented — erasure only).
    with_bad = good[: k - 1] + [Shard(7, bytes(bad))]
    result = decode(with_bad, k, n)
    assert result != data  # corrupted input must not round-trip silently


def test_deterministic_output():
    a = encode(b"same input bytes" * 10, k=3, n=6)
    b = encode(b"same input bytes" * 10, k=3, n=6)
    assert [s.data for s in a] == [s.data for s in b]


def test_parameter_validation():
    data = b"x" * 64
    with pytest.raises(ValueError):
        encode(data, k=0, n=3)
    with pytest.raises(ValueError):
        encode(data, k=5, n=4)  # n < k
    with pytest.raises(ValueError):
        encode(data, k=2, n=300)  # > 255 field points
    with pytest.raises(ValueError):
        decode([], k=2, n=4)  # no shards
    with pytest.raises(ValueError):
        shards = encode(data, k=2, n=4)
        decode(shards[:1], k=2, n=4)  # fewer than k
    with pytest.raises(ValueError):
        shards = encode(data, k=2, n=4)
        decode([shards[0], Shard(0, shards[0].data)], k=2, n=4)  # duplicate


def test_decode_requires_matching_length_headers():
    data = b"abc" * 30
    shards = encode(data, k=3, n=4)
    tampered = [Shard(s.index, s.data) for s in shards]
    bad = bytearray(tampered[1].data)
    bad[0] ^= 0x01  # corrupt the length header
    with pytest.raises(ValueError, match="length headers"):
        decode([tampered[0], Shard(tampered[1].index, bytes(bad)),
                tampered[2]], k=3, n=4)


def test_decode_infers_n_from_max_index():
    data = b"infer-n works" * 5
    shards = encode(data, k=3, n=7)
    # Without explicit n, uses max index + 1 — must still decode.
    assert decode(shards[:3], k=3) == data
    assert decode(shards[2:5], k=3) == data