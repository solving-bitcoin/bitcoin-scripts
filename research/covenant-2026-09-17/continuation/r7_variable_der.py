#!/usr/bin/env python3
"""Actual secp256k1 host algebra for variable-DER identities, not a covenant.

Deterministic inputs; no mining, Core, repository Script executor, or Rust tests.
The equidistribution estimates are explicitly models, not measured probabilities.
"""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import legacy_same_signature_counterexample as secp


def interval(length):
    """Exactly the positive integers with this minimal strict-DER byte length."""
    assert 1 <= length <= 24
    return (1 if length == 1 else 1 << (8 * length - 9),
            (1 << (8 * length - 1)) - 1)


def blob(r, s, flag):
    body = secp.signature_integer(r) + secp.signature_integer(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([flag])


def layout(size, rlen, slen, flag):
    assert rlen + slen + 7 == size
    r, s = interval(rlen)[0], interval(slen)[0]
    alpha = blob(r, s, flag)
    assert len(alpha) == size
    coefficient = 1 << (8 * (slen + 3))
    constant = int.from_bytes(alpha, "big") - coefficient * r - 256 * s
    assert 0 < constant < secp.N
    return coefficient, constant


def compressed(point):
    return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")


def affine_checks():
    rows = []
    for size, rlen, slen in [(32, 24, 1), (32, 21, 4),
                             (32, 12, 13), (20, 6, 7)]:
        rlo, rhi = interval(rlen)
        slo, shi = interval(slen)
        for flag in [0, 1, 2, 3, 129, 255]:
            a, c = layout(size, rlen, slen, flag)
            r, s = (rlo + rhi) // 2, (slo + shi) // 2
            alpha = blob(r, s, flag)
            z = int.from_bytes(alpha, "big")
            assert z == c + a * r + 256 * s
            valid, actual_r = secp.verify(z, r, s, secp.mul(-a))
            predicted = secp.mul(256 + c * pow(s, -1, secp.N))
            assert actual_r == predicted
            assert not valid
            rows.append({"size": size, "rlen": rlen, "slen": slen,
                         "flag": flag, "identity_holds": True,
                         "signature_valid": valid})
    return rows


def scan_small_s():
    """Exhaust all 127 positive one-byte s and all 256 flags, rlen=24.

    Changing the flag increments C0, hence R by (1/s)G. This scans all flags
    with one extra point per s instead of 256 full scalar multiplications.
    It is an exact arithmetic optimization, not a claim about larger searches.
    """
    a, c0 = layout(32, 24, 1, 0)
    rlo, rhi = interval(24)
    digest = hashlib.sha256()
    hits, infinity, x_above_n = [], 0, 0
    for s in range(1, 128):
        inv_s = pow(s, -1, secp.N)
        step = secp.mul(inv_s)
        point = secp.mul(256 + c0 * inv_s)
        for flag in range(256):
            if point is None:
                infinity += 1
                digest.update(b"\0" * 33)
            else:
                digest.update(compressed(point))
                r = point[0] % secp.N
                x_above_n += point[0] >= secp.N
                if rlo <= r <= rhi:
                    alpha = blob(r, s, flag)
                    z = int.from_bytes(alpha, "big")
                    assert secp.verify(z, r, s, secp.mul(-a))[0]
                    hits.append(alpha.hex())
            point = secp.add(point, step)
    assert not hits
    return {"size": 32, "rlen": 24, "slen": 1,
            "positive_s_values": 127, "flags": 256,
            "candidate_points": 127 * 256, "valid_der_digest_identities": hits,
            "infinite_points": infinity, "points_with_x_at_least_n": x_above_n,
            "ordered_point_transcript_sha256": digest.hexdigest(),
            "all_layouts_or_full_s_domain_enumerated": False}


def half_generator_obstruction():
    k = pow(2, -1, secp.N)
    nonce = secp.mul(k)
    r = nonce[0] % secp.N
    assert len(secp.signature_integer(r)) - 2 == 21
    assert r + secp.N >= secp.P  # No additional r+n x branch for this r.
    slo, shi = interval(4)
    rows = []
    for sign in [1, -1]:
        coefficient = 512 - sign
        for flag in range(256):
            _, c = layout(32, 21, 4, flag)
            low, high = 2 * c + coefficient * slo, 2 * c + coefficient * shi
            assert 0 < low <= high < secp.N
            rows.append({"nonce_sign": sign, "flag": flag,
                         "residual_min": str(low), "residual_max": str(high)})
    return {"r_hex": hex(r), "r_der_bytes": 21, "s_der_bytes": 4,
            "r_plus_n_below_field": False,
            "all_512_flag_sign_intervals_exclude_zero_mod_n": True,
            "checked_flag_sign_intervals": len(rows),
            "overall_residual_min": str(min(int(row["residual_min"]) for row in rows)),
            "overall_residual_max": str(max(int(row["residual_max"]) for row in rows))}


def variable_key_examples():
    """Cheap self-digest targets, and actual tx digests with free recovery keys.

    No target is claimed to be a hash, and tx outpoints here are synthetic.
    """
    k = pow(2, -1, secp.N)
    nonce = secp.mul(k)
    r = nonce[0] % secp.N
    slo = interval(4)[0]
    identities = []
    for flag in [0, 1, 2, 3, 129, 255]:
        s = slo + flag
        alpha = blob(r, s, flag)
        assert len(alpha) == 32
        z = int.from_bytes(alpha, "big")
        key_scalar = (s * k - z) * pow(r, -1, secp.N) % secp.N
        key = secp.mul(key_scalar)
        assert secp.verify(z, r, s, key)[0]
        identities.append({"flag": flag, "alpha_hex": alpha.hex(),
                           "key_hex": compressed(key).hex(),
                           "self_digest_signature_valid": True,
                           "known_hash_preimage": False})
    # One fixed DER signature is valid for each actual legacy ALL hash if
    # its recovery key is allowed to vary. This does not enforce alpha=z.
    s, flag = slo + 1, 1
    alpha = blob(r, s, flag)
    fixed_z = int.from_bytes(alpha, "big")
    fixed_key = secp.mul((s * k - fixed_z) * pow(r, -1, secp.N))
    native_rows = []
    for output_script in [b"\x51", b"\x52"]:
        preimage = secp.tx(b"\xac", output_script) + struct.pack("<I", flag)
        hashed = secp.hash256(preimage)
        native_z = int.from_bytes(hashed, "big")
        recovery_key = secp.mul((s * k - native_z) * pow(r, -1, secp.N))
        assert secp.verify(native_z, r, s, recovery_key)[0]
        fixed_accepts = secp.verify(native_z, r, s, fixed_key)[0]
        assert not fixed_accepts and hashed != alpha
        native_rows.append({"output_script_hex": output_script.hex(),
                            "legacy_all_digest_hex": hashed.hex(),
                            "recovery_key_hex": compressed(recovery_key).hex(),
                            "variable_key_accepts": True,
                            "fixed_self_digest_key_accepts": False,
                            "alpha_equals_native_hash": False})
    return {"actual_curve": "secp256k1", "synthetic_funding_outpoint": True,
            "self_digest_examples": identities, "native_hash_examples": native_rows}


def cardinalities():
    rows = []
    for size in [20, 32]:
        total = 0
        layouts = []
        for slen in range(1, size - 7):
            rlen = size - 7 - slen
            rlo, rhi = interval(rlen)
            slo, shi = interval(slen)
            pairs = (rhi - rlo + 1) * (shi - slo + 1)
            total += 256 * pairs
            layouts.append({"rlen": rlen, "slen": slen,
                            "positive_r_count": str(rhi - rlo + 1),
                            "positive_s_count": str(shi - slo + 1),
                            "pairs_per_flag": str(pairs),
                            "equidistribution_expected_solutions_per_flag": pairs / secp.N})
        rows.append({"size": size, "layouts": layouts,
                     "strict_der_nonzero_r_s_all_flags_count": str(total),
                     "equidistribution_expected_all_layout_solutions": total / secp.N,
                     "equidistribution_expected_all_layout_solutions_log2": math.log2(total / secp.N),
                     "this_is_a_model_not_a_secp_lower_bound": True})
    return rows


def main():
    result = {
        "question": "Solve variable-DER self-digest equations and bind actual output-specific hashes",
        "evidence": "locally-reproduced", "deployment": "unclassified",
        "deterministic": True, "rng_used": False,
        "native_hash_or_der_mining_performed": False,
        "script_metrics": {"locking_script_bytes": None, "serialized_witness_bytes": None,
                           "entry_data_items": None, "hint_items": None,
                           "combined_stack_peak": None, "executed_opcodes": None,
                           "reason": "Host algebra experiment; no executable Script candidate supplied"},
        "affine_equation_checks": affine_checks(),
        "complete_one_byte_s_scan": scan_small_s(),
        "half_generator_obstruction": half_generator_obstruction(),
        "variable_key_examples": variable_key_examples(),
        "finite_der_domains": cardinalities(),
        "target_matching_model": {"equation": "E <= Q_setup * Q_tx / 2^256",
                                  "at_total_work_2pow64": 2 ** -130,
                                  "granting_all_native_digest_branches_upper_bound": 2 ** -127,
                                  "branch_grant": "At most four nonce points and two 256-bit representations per scalar",
                                  "scope": "Preselected target blobs independent of fresh ideal native hashes"},
        "source": {"url": "https://www.secg.org/sec1-v2.pdf", "version": "2.0, 2009-05-21",
                   "sections": "4.1.4-4.1.7"},
    }
    Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"affine_checks": len(result["affine_equation_checks"]),
                      "candidate_points": result["complete_one_byte_s_scan"]["candidate_points"],
                      "hits": len(result["complete_one_byte_s_scan"]["valid_der_digest_identities"]),
                      "half_generator_intervals": result["half_generator_obstruction"]["checked_flag_sign_intervals"],
                      "variable_key_identities": len(result["variable_key_examples"]["self_digest_examples"]),
                      "native_hash_cases": len(result["variable_key_examples"]["native_hash_examples"])}, indent=2))


if __name__ == "__main__":
    main()
