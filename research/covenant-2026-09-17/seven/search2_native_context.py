#!/usr/bin/env python3
"""Host-only tests of native preimage equality and funding dependencies.

These fixtures do not execute Script or establish consensus validity. The
serializer models Bitcoin Core 30.3 legacy semantics. All inputs are public,
deterministic, and synthetic. No random search or witness hints are used.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import struct


CORE = "49faec4f87f5cd19c88db01a82e5c68b087c8227"
BUG = b"\x01" + b"\x00" * 31


def h256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b"\xfd" + struct.pack("<H", value)
    return b"\xfe" + struct.pack("<I", value)


def vector(data):
    return compact(len(data)) + data


def push(data):
    assert len(data) <= 75
    return bytes([len(data)]) + data


def instructions(script):
    cursor = 0
    while cursor < len(script):
        start = cursor
        opcode = script[cursor]
        cursor += 1
        if opcode <= 75:
            cursor += opcode
        elif opcode in (76, 77, 78):
            size = 1 << (opcode - 76)
            count = int.from_bytes(script[cursor:cursor + size], "little")
            cursor += size + count
        assert cursor <= len(script), "fixture has truncated push"
        yield start, cursor, opcode


def delete(script, signatures):
    # A serialized signature push is a whole instruction in these fixtures.
    for signature in signatures:
        target = push(signature)
        script = b"".join(script[a:b] for a, b, _ in instructions(script)
                          if script[a:b] != target)
    return script


def clean(script):
    return b"".join(script[a:b] for a, b, op in instructions(script)
                    if op != 0xab)


def output_bytes(output):
    value, script = output
    return struct.pack("<Q", value) + vector(script)


def legacy_preimage(inputs, outputs, index, script_code, flag, version=2, locktime=0):
    """Return None for SINGLE bug, else the exact double-SHA256 input."""
    base = flag & 31
    if base == 3 and index >= len(outputs):
        return None
    selected = [index] if flag & 128 else range(len(inputs))
    out = struct.pack("<I", version) + compact(len(selected))
    for j in selected:
        prevout, sequence = inputs[j]
        out += prevout + vector(clean(script_code) if j == index else b"")
        out += struct.pack("<I", 0 if j != index and base in (2, 3) else sequence)
    if base == 2:
        out += b"\x00"
    elif base == 3:
        out += compact(index + 1)
        out += (b"\xff" * 8 + b"\x00") * index
        out += output_bytes(outputs[index])
    else:
        out += compact(len(outputs)) + b"".join(map(output_bytes, outputs))
    return out + struct.pack("<II", locktime, flag)


def token(preimage):
    # Tag the special digest separately from an ordinary preimage.
    return ("constant", BUG) if preimage is None else ("preimage", preimage)


def partition(tokens):
    labels = {}
    return [labels.setdefault(item, len(labels)) for item in tokens]


def run():
    inputs = [(bytes([i + 1]) * 32 + struct.pack("<I", i), 0x80000000 + i)
              for i in range(3)]
    outputs_a = [(1234, b"\x00\x14" + b"\x11" * 20),
                 (5678, b"\x00\x20" + b"\x22" * 32)]
    # Preserve output count but change amounts, scripts, and script lengths.
    outputs_b = [(1200, b"\x51"), (5700, b"\x00\x14" + b"\x33" * 20)]
    sigs = [bytes.fromhex("300602010102010103"),
            bytes.fromhex("300602010202010103"),
            bytes.fromhex("300602010302010103")]
    embedded = b"".join(map(push, sigs))
    # Includes a push containing the entire signature push: no recursive deletion.
    scripts = [embedded + b"\xab\xac", b"\x51" + embedded + b"\xac",
               push(push(sigs[0])) + b"\xab\xac", b"\xab\xac", b"\xac", b""]
    contexts = []
    for i, flag, script_index, mask in itertools.product(range(3), range(256), range(len(scripts)), range(8)):
        chosen = [s for j, s in enumerate(sigs) if mask >> j & 1]
        contexts.append((i, flag, script_index, mask, delete(scripts[script_index], chosen)))
    values = []
    for outputs in (outputs_a, outputs_b):
        values.append([token(legacy_preimage(inputs, outputs, i, code, flag))
                       for i, flag, _, _, code in contexts])
    assert partition(values[0]) == partition(values[1])
    groups = defaultdict(int)
    for a in values[0]:
        groups[a] += 1
    preserved_pairs = sum(n * (n - 1) // 2 for n in groups.values())
    # Even semantic-equivalent undefined flags differ in the 4-byte trailer.
    flag_cases = []
    for flag in (0, 1, 4, 33, 65, 97):
        preimage = legacy_preimage(inputs, outputs_a, 0, b"\xac", flag)
        flag_cases.append({"flag": flag, "trailer": preimage[-4:].hex(),
                           "digest": h256(preimage).hex()})
    assert len({row["digest"] for row in flag_cases}) == len(flag_cases)
    assert len({legacy_preimage(inputs, outputs_a, 0, b"\xac", row["flag"])[:-4]
                for row in flag_cases}) == 1
    # Signature removal is local to one CHECKMULTISIG copy, not a mutation
    # of the executed locking script or a persistent cross-check state.
    first = delete(scripts[0], [sigs[0]])
    second = delete(scripts[0], [sigs[1]])
    cumulative = delete(first, [sigs[1]])
    assert second != cumulative and push(sigs[0]) in second
    assert delete(scripts[2], [sigs[0]]) == scripts[2]
    # Model the funding circularity with a constant after CODESEPARATOR.
    # Even omitting the changed constant from the spend's scriptCode cannot
    # omit it from the previous transaction's txid.
    funding_txids = []
    spending_digests = []
    for allowed_subset in (b"\x01", b"\x02"):
        locking_script = push(allowed_subset) + b"\x75\xab\xac"
        funding = (struct.pack("<I", 2) + b"\x01" + bytes([0x42]) * 36
                   + b"\x00" + b"\xff" * 4 + b"\x01"
                   + output_bytes((10000, locking_script)) + b"\x00" * 4)
        prevout = h256(funding) + b"\x00" * 4
        funding_txids.append(h256(funding)[::-1].hex())
        preimage = legacy_preimage([(prevout, 0xffffffff)], outputs_a, 0, b"\xac", 1)
        spending_digests.append(h256(preimage).hex())
    assert funding_txids[0] != funding_txids[1]
    assert spending_digests[0] != spending_digests[1]
    return {
        "question": "Can legacy native preimage equality, subset deletion, or post-mining subset commitments distinguish predetermined outputs?",
        "evidence": "locally-reproduced", "deployment_class": "unclassified",
        "boundary": "Host serializer only, synthetic public transactions; no Script execution or covenant claimed.",
        "core_semantics_reference": CORE,
        "all_assertions_passed": True,
        "context_count_per_output_variant": len(contexts),
        "input_count": len(inputs), "output_count": len(outputs_a),
        "full_sighash_bytes_tested": 256, "script_templates": len(scripts),
        "subset_masks_per_template": 8,
        "preimage_or_bug_equivalence_classes": len(groups),
        "equal_context_pairs_preserved_after_output_mutation": preserved_pairs,
        "preimage_equality_partition_unchanged": True,
        "semantic_equivalent_flags": flag_cases,
        "find_and_delete_is_check_local": True,
        "embedded_signature_push_is_not_deleted": True,
        "funding_dependency": {"script_code_in_both_spends": "ac",
                               "funding_txids": funding_txids,
                               "spending_digests": spending_digests},
        "hint_items": 0, "witness_bytes": 0,
        "script_bytes": None, "combined_stack_peak": None,
        "executed_opcodes": None,
        "resource_note": "Not a complete locking script; Script metrics are inapplicable, not zero.",
    }


if __name__ == "__main__":
    report = run()
    path = Path(__file__).with_suffix(".json")
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
