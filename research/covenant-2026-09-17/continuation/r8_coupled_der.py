#!/usr/bin/env python3
"""Deterministic real-curve model of two coupled short DER signatures.

Synthetic digest identities only: no hash mining, Script, Core or field tests.
"""
import hashlib
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import legacy_same_signature_counterexample as secp
from r7_variable_der import blob, compressed, interval, layout


def main():
    r = secp.mul(pow(2, -1, secp.N))[0] % secp.N
    assert len(secp.signature_integer(r)) - 2 == 21
    assert r + secp.N >= secp.P
    slo, shi = interval(4)
    cases = []
    for sign in [1, -1]:
        k = sign * pow(2, -1, secp.N) % secp.N
        for q in [2, 3, 5]:
            a = (512 - sign * q) * pow(512 - sign, -1, secp.N) % secp.N
            for flag in [0, 1, 2, 3, 129, 255]:
                coefficient, constant = layout(32, 21, 4, flag)
                base = (coefficient + constant * pow(r, -1, secp.N)) % secp.N
                for s in [slo, slo + 17, shi // q]:
                    alpha, beta = blob(r, s, flag), blob(r, q * s, flag)
                    assert len(alpha) == len(beta) == 32 and alpha != beta
                    z = int.from_bytes(alpha, "big")
                    d1 = ((k - 256) * s * pow(r, -1, secp.N) - base) % secp.N
                    d2 = (a * d1 + (a - 1) * base) % secp.N
                    p1, p2 = secp.mul(d1), secp.mul(d2)
                    assert p1 != p2
                    assert secp.add(secp.mul(a, p1), secp.mul((a - 1) * base)) == p2
                    valid1, nonce1 = secp.verify(z, r, s, p1)
                    valid2, nonce2 = secp.verify(z, r, q * s, p2)
                    assert valid1 and valid2 and nonce1 == nonce2 == secp.mul(k)
                    assert int.from_bytes(beta, "big") - z == 256 * (q - 1) * s
                    # If committed d1 is fixed, each possible nonce sign leaves
                    # exactly one candidate self-digest s modulo n.
                    recovered_s = ((constant + coefficient * r + r * d1)
                                   * pow(k - 256, -1, secp.N)) % secp.N
                    assert recovered_s == s
                    hash_chain_matches = hashlib.sha256(alpha).digest() == beta
                    assert not hash_chain_matches
                    cases.append({"nonce_sign": sign, "q": q, "flag": flag,
                                  "s": s, "alpha_hex": alpha.hex(), "beta_hex": beta.hex(),
                                  "p1_hex": compressed(p1).hex(), "p2_hex": compressed(p2).hex(),
                                  "both_verify_on_int_alpha": True,
                                  "affine_point_relation_holds": True,
                                  "fixed_key_recovers_unique_s_for_this_nonce_sign": True,
                                  "beta_equals_sha256_alpha": False,
                                  "known_hash_preimages": False})
    # q=1 makes both signatures and both keys identical; no second relation.
    for sign in [1, -1]:
        assert ((512 - sign) * pow(512 - sign, -1, secp.N)) % secp.N == 1
    domain_rows = []
    for q in [2, 3, 5]:
        count = shi // q - slo + 1
        domain_rows.append({"q": q, "fixed_flag_fixed_r_alpha_values": count,
                           "uniform_native_hash_hit_probability": count / 2 ** 256,
                           "uniform_native_hash_trials_log2": 256 - math.log2(count),
                           "random_sha256_chain_expected_matching_pairs": count / 2 ** 256,
                           "independent_roots_expected_matches_at_total_queries_2pow64":
                               count * 2 ** 126 / 2 ** 512})
    result = {
        "question": "Can affine related keys couple two short DER signatures and cancel the layout constant?",
        "evidence": "locally-reproduced", "deployment": "unclassified",
        "curve": "secp256k1", "deterministic": True, "rng_used": False,
        "hash_mining_performed": False, "bitcoin_core_executed": False,
        "r_hex": hex(r), "r_plus_n_below_field": False,
        "real_curve_cases": len(cases), "cases": cases,
        "q_one_degenerates_to_identical_signature_and_key": True,
        "cost_models": domain_rows,
        "model_scope": "Fixed r=x(G/2), fixed preselected flag, both strict-DER integer lengths 21/4",
        "script_metrics": {"locking_script_bytes": None, "witness_bytes": None,
                           "entry_data_items": None, "hint_items": None,
                           "stack_peak": None, "opcodes": None,
                           "reason": "No Script implementing the affine key and byte relations supplied"},
    }
    Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"real_curve_cases": len(cases),
                      "q_one_degenerates": True, "cost_models": domain_rows}, indent=2))


if __name__ == "__main__":
    main()
