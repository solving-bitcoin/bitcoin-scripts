#!/usr/bin/env python3
"""Deterministic host checks of the legacy/BIP143 overlap obstruction."""
import json
from pathlib import Path
import struct

from search2_native_context import compact, h256, legacy_preimage, output_bytes, vector


def bip143(inputs, outputs, index, code, amount, flag):
    base, acp = flag & 31, bool(flag & 128)
    prevouts = b"\0" * 32 if acp else h256(b"".join(u for u, _ in inputs))
    sequences = (b"\0" * 32 if acp or base in (2, 3) else
                 h256(b"".join(struct.pack("<I", s) for _, s in inputs)))
    if base not in (2, 3):
        outputs_hash = h256(b"".join(map(output_bytes, outputs)))
    elif base == 3 and index < len(outputs):
        outputs_hash = h256(output_bytes(outputs[index]))
    else:
        outputs_hash = b"\0" * 32
    outpoint, sequence = inputs[index]
    return (struct.pack("<I", 2) + prevouts + sequences + outpoint + vector(code)
            + struct.pack("<QI", amount, sequence) + outputs_hash
            + struct.pack("<II", 0, flag))


def parsed_transaction_end(data):
    """Parse exactly one stripped transaction, retaining trailing bytes."""
    pos = 4

    def take(n):
        nonlocal pos
        assert pos + n <= len(data)
        result = data[pos:pos+n]
        pos += n
        return result

    def count():
        first = take(1)[0]
        if first < 253:
            return first
        n = int.from_bytes(take({253: 2, 254: 4, 255: 8}[first]), "little")
        assert n >= {253: 253, 254: 65536, 255: 2**32}[first]
        return n

    for _ in range(count()):
        take(36)
        take(count())
        take(4)
    for _ in range(count()):
        take(8)
        take(count())
    take(4)
    return pos


def main():
    checked = acp_impossible = non_acp_prefix = bug = trailers = 0
    samples = []
    for m in (1, 2, 252, 253, 1000):
        inputs = [(h256(b"search5/prevout/" + struct.pack("<I", i))
                   + struct.pack("<I", i), 0xfffffffe - i) for i in range(m)]
        outputs = [(12345, b"\x51"), (45678, b"\x00\x14" + b"\x22" * 20)]
        for i in sorted({0, m-1}):
            for flag in range(256):
                legacy = legacy_preimage(inputs, outputs, i, b"\x51", flag)
                native = bip143(inputs, outputs, 0, b"\x51", 999999, flag)
                if legacy is None:
                    bug += 1
                    continue
                assert legacy[:4] == native[:4]
                assert legacy[-4:] == native[-4:] == struct.pack("<I", flag)
                end = parsed_transaction_end(legacy)
                assert end == len(legacy) - 4
                assert legacy[end:] == struct.pack("<I", flag)
                trailers += 1
                if flag & 128:
                    assert native[4:36] == b"\0" * 32
                    assert legacy[4] == 1
                    acp_impossible += 1
                else:
                    prefix = compact(m)
                    target = prefix + inputs[0][0][:32-len(prefix)]
                    assert legacy[4:36] == target
                    assert native[4:36] == h256(b"".join(u for u, _ in inputs))
                    assert legacy[4:36] != native[4:36]
                    non_acp_prefix += 1
                assert legacy != native
                checked += 1
        samples.append({"inputs": m, "count_bytes": compact(m).hex(),
                        "self_dependent_txid_prefix_bytes": 32-len(compact(m))})
    report = {
        "evidence": "locally-reproduced", "deployment": "unclassified",
        "boundary": "Host serialization only; synthetic public data; no Script execution.",
        "core_reference": "49faec4f87f5cd19c88db01a82e5c68b087c8227",
        "ordinary_cross_format_cases": checked,
        "acp_prefix_contradictions": acp_impossible,
        "non_acp_self_dependent_prefix_checks": non_acp_prefix,
        "legacy_single_bug_cases_excluded": bug,
        "legacy_preimages_with_exactly_four_trailing_bytes": trailers,
        "count_boundaries": samples,
        "hint_items": 0, "witness_bytes": 0,
        "script_metrics": "Not applicable: no complete script or witness exists.",
        "ideal_hash_model": {
            "necessary_event": "H(X) = CompactSize(len(X)/36) || X[:32-len(CompactSize(len(X)/36))]",
            "event_bits": 256,
            "union_bound": "Q / 2^256 for Q fresh ideal H256 queries",
            "bound_at_Q_2pow64": "2^-192",
            "scope": "Exact preimage overlap only; not distinct-preimage digest relations or SHA256 cryptanalysis."
        }
    }
    path = Path(__file__).with_suffix(".json")
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
