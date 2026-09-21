#!/usr/bin/env python3
"""Exact interval partition for fixed-nonce, shifted-key DER length probes.

This models the scalar signatures, granting the stronger assumption that the
nonce is fixed. It is not Bitcoin Script, a hash truncation primitive, or a
consensus execution. Every interval in the full secp256k1 scalar domain is
covered; this is not a random sampling experiment.
"""
import json
import math

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def length(value):
    value = min(value, N - value)
    if value == 0:
        return 0  # Distinguish the invalid ECDSA zero-s boundary.
    return (value.bit_length() + 7) // 8 + (value.bit_length() % 8 == 0)


def partition(count):
    offsets = [1 + j * N // count for j in range(count)]
    base_boundaries = {0, 1}
    for width in range(1, 32):
        threshold = 1 << (8 * width - 1)
        base_boundaries.update((threshold, N - threshold + 1))
    assert len(base_boundaries) == 64
    boundaries = sorted({(boundary - offset) % N
                         for boundary in base_boundaries for offset in offsets})
    vectors = set()
    covered = 0
    for index, start in enumerate(boundaries):
        following = boundaries[(index + 1) % len(boundaries)]
        interval_size = (following - start) % N
        assert interval_size > 0
        end = (start + interval_size - 1) % N
        at_start = tuple(length((start + offset) % N) for offset in offsets)
        at_end = tuple(length((end + offset) % N) for offset in offsets)
        assert at_start == at_end
        vectors.add(at_start)
        covered += interval_size
    assert covered == N
    assert len(boundaries) <= 64 * count
    assert len(vectors) <= len(boundaries)
    return {"offset_keys": count, "scalar_domain_size": str(N),
            "intervals": len(boundaries), "distinct_length_vectors": len(vectors),
            "max_information_bits": math.log2(len(vectors)),
            "general_bound_bits": math.log2(64 * count)}


if __name__ == "__main__":
    print(json.dumps({
        "evidence": "locally-reproduced",
        "deployment_class": "unclassified",
        "scope": "Exact scalar-domain partition; no Bitcoin Script execution.",
        "results": [partition(count) for count in (1, 2, 4, 8, 16, 32, 64, 128)],
    }, indent=2))
