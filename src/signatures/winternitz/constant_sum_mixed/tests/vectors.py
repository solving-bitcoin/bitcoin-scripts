#!/usr/bin/env python3
"""Independent exact checks for the retained mixed constant-sum candidate."""

from collections import Counter
from math import factorial, log2

M = 45
N = 45
Q = 12
FIXED = (23, 38, 44)
PAIRS = (
    (42, 27, 12), (39, 17, 4), (39, 15, 20), (40, 27, 8),
    (27, 41, 2), (33, 41, 2), (41, 26, 10), (21, 5, 12),
    (31, 37, 2), (42, 19, 14), (43, 25, 8), (43, 34, 6),
    (39, 41, 2), (13, 29, 12), (11, 33, 4),
)
EXPECTED = 1474534644173396013943101947755055475538944000000


def histogram(mask):
    counts = Counter(FIXED)
    counts[M] = Q
    for index, (u, v, shift) in enumerate(PAIRS):
        if mask >> index & 1:
            counts[u - shift] += 1
            counts[v + shift] += 1
        else:
            counts[u] += 1
            counts[v] += 1
    return tuple(counts[digit] for digit in range(M + 1))


def multinomial(counts):
    result = factorial(N)
    for count in counts:
        result //= factorial(count)
    return result


def main():
    classes = [histogram(mask) for mask in range(1 << len(PAIRS))]
    assert len(set(classes)) == 32768
    assert all(sum(counts) == N for counts in classes)
    assert {sum(i * count for i, count in enumerate(counts)) for counts in classes} == {1566}
    capacity = sum(map(multinomial, classes))
    assert capacity == EXPECTED
    assert capacity >= 1 << 160
    wide = sum(classes[0][d] for d in range(1, M) if (M - d) % 2 == 1)
    assert wide == 7
    hash_ops = sum((M - d + 1) // 2 for d in FIXED)
    hash_ops += sum((M - u + 1) // 2 + (M - v + 1) // 2 for u, v, _ in PAIRS)
    assert hash_ops == 233
    staged_script = 21 * N + 6 * (N - Q) + hash_ops + (Q + 1) // 2 + 3 + 7 * len(PAIRS)
    maximum_witness = 1 + 23 * (N - Q) + 12 * wide
    assert (staged_script, maximum_witness) == (1490, 844)
    print(f"classes={len(classes)} capacity={capacity} bits={log2(capacity):.12f}")
    print(f"entry={staged_script + 1} staged={staged_script} witness={maximum_witness}")


if __name__ == "__main__":
    main()
