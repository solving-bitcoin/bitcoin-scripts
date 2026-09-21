#!/usr/bin/env python3
"""Finite-curve tests for a correlated hash/signature cycle, not Bitcoin validation.

The hash-to-signature adapter is an explicitly artificial small-model adapter.
It is not SHA256-to-DER mining, and the curve is not secp256k1. No repository
Script executor, disabled checks, Rust tests, or field-arithmetic tests are used.
"""
import hashlib
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import legacy_same_signature_counterexample as secp

FIELD = 211
ORDER = 199
BASE = (3, 33)
SEED = b"bitcoin-lab/r6-correlated-root/2026-09-17/v1"
RAW_SCRIPT = "6e7ca87cada87cac"


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % FIELD == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, FIELD) if a == b else
             (v - y) * pow(u - x, -1, FIELD)) % FIELD
    nx = (slope * slope - x - u) % FIELD
    return nx, (slope * (x - nx) - y) % FIELD


POINTS = [None]
for _ in range(1, ORDER):
    POINTS.append(add(POINTS[-1], BASE))
assert add(POINTS[-1], BASE) is None
assert len(set(POINTS)) == ORDER
assert sum(1 for x in range(FIELD) for y in range(FIELD)
           if (y * y - x * x * x - 7) % FIELD == 0) + 1 == ORDER
LOG = {point: index for index, point in enumerate(POINTS)}
ROOTS = {r: [k for k, point in enumerate(POINTS[1:], 1)
             if point[0] % ORDER == r] for r in range(1, ORDER)}


def enc(index):
    x, y = POINTS[index]
    return bytes([2 + y % 2, x])


def alpha(index):
    # Artificial adapter: a 1/4 gate, nonzero small r/s, and fixed ALL flag.
    # Granting the flag avoids confusing a flag attack with the cycle issue.
    digest = hashlib.sha256(SEED + enc(index)).digest()
    if digest[0] & 3:
        return None
    return (1 + int.from_bytes(digest[1:3], "big") % (ORDER - 1),
            1 + int.from_bytes(digest[3:5], "big") % (ORDER - 1), 1)


ALPHAS = {i: alpha(i) for i in range(1, ORDER)}


def verify(z, signature, key):
    if signature is None or key == 0:
        return False
    r, s, _ = signature
    rpoint = POINTS[((z + r * key) * pow(s, -1, ORDER)) % ORDER]
    return rpoint is not None and rpoint[0] % ORDER == r


def successors(z, index):
    signature = ALPHAS[index]
    if signature is None:
        return set()
    r, s, _ = signature
    # All r and r+n x branches, each with both signs, are present in ROOTS.
    return {q for nonce in ROOTS[r]
            if (q := ((s * nonce - z) * pow(r, -1, ORDER)) % ORDER)}


def execute_two_cycle(z, p0, p1):
    # Exact stack routing of the proposed eight-opcode script. SHA256 is
    # replaced by alpha() and CHECKSIG by the finite-curve verifier.
    stack = [p0, p1]
    peak = len(stack)
    stack += stack[-2:]                 # 2DUP
    peak = max(peak, len(stack))
    stack[-1], stack[-2] = stack[-2], stack[-1]
    stack[-1] = ALPHAS[stack[-1]]       # SHA256 (model adapter)
    stack[-1], stack[-2] = stack[-2], stack[-1]
    key, signature = stack.pop(), stack.pop()
    if not verify(z, signature, key):   # CHECKSIGVERIFY
        return False, peak
    stack[-1] = ALPHAS[stack[-1]]       # SHA256 (model adapter)
    stack[-1], stack[-2] = stack[-2], stack[-1]
    key, signature = stack.pop(), stack.pop()
    stack.append(verify(z, signature, key))
    return stack == [True], peak


def self_digest_identity():
    """Actual secp256k1 algebra; these synthetic DER blobs are not mined hashes."""
    nonce = secp.mul(256)
    nonce_r = nonce[0] % secp.N
    cases = []
    for size, rlen, slen in [(32, 10, 15), (20, 6, 7)]:
        r = 2 ** (8 * (rlen - 1)) + 3
        for flag in [1, 2, 3, 129]:
            sig0 = (b"\x30" + bytes([size - 3, 2, rlen]) + r.to_bytes(rlen, "big")
                    + bytes([2, slen]) + (2 ** (8 * (slen - 1))).to_bytes(slen, "big")
                    + bytes([flag]))
            assert len(sig0) == size
            constant = int.from_bytes(sig0, "big") - 256 * 2 ** (8 * (slen - 1))
            key = secp.mul(-constant * pow(r, -1, secp.N))
            for s in [2 ** (8 * (slen - 1)), 2 ** (8 * (slen - 1)) + 1,
                      2 ** (8 * slen - 2) + 123]:
                blob = sig0[:-(slen + 1)] + s.to_bytes(slen, "big") + bytes([flag])
                z = int.from_bytes(blob, "big")
                assert z == constant + 256 * s
                valid, point = secp.verify(z, r, s, key)
                assert point == nonce
                assert not valid
                cases.append({"hash_size": size, "r_bytes": rlen,
                              "s_bytes": slen, "flag": flag,
                              "synthetic_der_hex": blob.hex(),
                              "recovered_nonce_is_256G": True,
                              "signature_valid": valid})
    return {"actual_secp256k1": True, "mined_hashes": False,
            "nonce_256G": [hex(v) for v in nonce],
            "required_r_hex": hex(nonce_r),
            "required_unsigned_r_bytes": (nonce_r.bit_length() + 7) // 8,
            "required_der_r_bytes": len(secp.signature_integer(nonce_r)) - 2,
            "maximum_r_bytes_for_32byte_signature_with_nonzero_s": 24,
            "maximum_r_bytes_for_20byte_signature_with_nonzero_s": 12,
            "checked_cases": len(cases), "cases": cases}


def main():
    rows = []
    example = None
    edge_checks = 0
    acceptance_checks = 0
    for z in range(ORDER):
        edges = {i: successors(z, i) for i in range(1, ORDER)}
        loops = [i for i in edges if i in edges[i]]
        pairs = [(i, j) for i in edges for j in edges[i]
                 if i < j and i in edges[j]]
        for i, destinations in edges.items():
            signature = ALPHAS[i]
            if signature is None:
                continue
            r, s, _ = signature
            for q in destinations:
                assert verify(z, signature, q)
                # Direct-root list targets meet zG exactly when q == i.
                targets = {(s * nonce - r * i) % ORDER for nonce in ROOTS[r]}
                assert (z in targets) == (i in destinations)
                edge_checks += 1
        for i, j in pairs:
            assert execute_two_cycle(z, i, j) == (True, 4)
            acceptance_checks += 1
            if example is None:
                wrong = next(k for k in range(1, ORDER)
                             if not execute_two_cycle(z, i, k)[0])
                assert execute_two_cycle(z, i, wrong)[0] is False
                example = {"z": z, "point_indices": [i, j],
                           "points": [POINTS[i], POINTS[j]],
                           "model_signatures": [ALPHAS[i], ALPHAS[j]],
                           "wrong_second_key_index": wrong,
                           "same_script_model_accepts": True,
                           "wrong_key_rejected": True}
        rows.append({"z": z, "edges": sum(map(len, edges.values())),
                     "self_loops": len(loops), "distinct_two_cycles": len(pairs)})
    assert example is not None
    p_der = 780555 / 2**65
    # Two independent batch lists: b*p_der*Q_key*Q_tx / n expected matches.
    b = 4  # Favorable maximum, not an average measured recovery count.
    total_at_one_expected_match_log2 = 1 + (256 - math.log2(b * p_der)) / 2
    data = {
        "question": "Can correlated root/key hash predicates avoid a second rare gate?",
        "evidence": "locally-reproduced", "deployment": "unclassified",
        "model_only": True,
        "curve": {"p": FIELD, "n": ORDER, "a": 0, "b": 7, "G": BASE},
        "seed_hex": SEED.hex(),
        "adapter": "SHA256(seed||compressed tiny point), low two bits zero, mapped r/s, fixed ALL",
        "raw_proposed_script": RAW_SCRIPT,
        "inspected_fragment_metrics": {"bytes": 8, "static_non_push_opcodes": 8,
                                       "entry_data_items": 2, "hint_items": 0,
                                       "combined_stack_peak": 4,
                                       "complete_bitcoin_witness_bytes": None},
        "hash_admissible_keys": sum(s is not None for s in ALPHAS.values()),
        "recovery_branch_counts": sorted(set(map(len, ROOTS.values()))),
        "all_scalar_contexts": len(rows),
        "verified_recovery_edges": edge_checks,
        "accepted_two_cycle_models": acceptance_checks,
        "two_cycle_example": example,
        "aggregate_self_loops": sum(row["self_loops"] for row in rows),
        "aggregate_distinct_two_cycles": sum(row["distinct_two_cycles"] for row in rows),
        "contexts_with_self_loop": sum(row["self_loops"] > 0 for row in rows),
        "contexts_with_two_cycle": sum(row["distinct_two_cycles"] > 0 for row in rows),
        "ideal_batch_estimate": {"der_probability": p_der,
            "favorable_branches_per_key": b,
            "total_raw_queries_log2_for_one_expected_match": total_at_one_expected_match_log2,
            "expected_matches_with_2pow64_total_queries": b * p_der * 2**126 / 2**256,
            "universal_lower_bound": False},
        "self_digest_affine_identity": self_digest_identity(),
        "per_scalar": rows,
    }
    target = Path(__file__).with_suffix(".json")
    target.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({key: data[key] for key in (
        "all_scalar_contexts", "verified_recovery_edges", "accepted_two_cycle_models",
        "aggregate_self_loops", "aggregate_distinct_two_cycles", "two_cycle_example",
        "ideal_batch_estimate")}, indent=2))


if __name__ == "__main__":
    main()
