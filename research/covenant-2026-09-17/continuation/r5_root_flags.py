#!/usr/bin/env python3
"""Host-only R5 flag accounting and a narrow SINGLE-bug rejection guard.

No hash preimage is asserted for synthetically modified signature flags. The
one unchanged public SHA256 preimage is explicitly identified in the output.
No Script executor or Bitcoin consensus claim is used by this file.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ec = module("r5_ec", ROOT / "legacy_same_signature_counterexample.py")
sighash = module("r5_sighash", ROOT / "seven/search2_native_context.py")
PREIMAGE = bytes.fromhex("00000000000000000200a8013bbb8678")
ALPHA = hashlib.sha256(PREIMAGE).digest()
FRAGMENT = bytes.fromhex("6eadabac91")
WRAPPER = bytes.fromhex("7ca87c") + FRAGMENT


def lift(x):
    if x >= ec.P:
        return None
    y = pow((pow(x, 3, ec.P) + 7) % ec.P, (ec.P + 1) // 4, ec.P)
    if y * y % ec.P != (pow(x, 3, ec.P) + 7) % ec.P:
        return None
    return (x, y if y % 2 == 0 else ec.P - y)


def parse(sig):
    assert sig[0] == 0x30 and sig[1] == len(sig) - 3 and sig[2] == 2
    nr = sig[3]
    assert sig[4 + nr] == 2
    ns = sig[5 + nr]
    assert nr + ns + 7 == len(sig)
    return int.from_bytes(sig[4:4 + nr], "big"), int.from_bytes(sig[6 + nr:6 + nr + ns], "big"), sig[-1]


def digest(inputs, outputs, index, code, flag):
    pre = sighash.legacy_preimage(inputs, outputs, index, code, flag)
    return sighash.BUG if pre is None else sighash.h256(pre)


def recovery(r, s, z, nonce):
    return ec.mul(pow(r, -1, ec.N), ec.add(ec.mul(s, nonce), ec.mul(-z)))


def ser(point):
    return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")


def run():
    inputs = [(bytes([j + 1]) * 32 + struct.pack("<I", j), 0xfffffffe - j)
              for j in range(2)]
    outputs = [(10000, bytes.fromhex("0014") + b"\x11" * 20)]
    flags_all = [f for f in range(256) if f & 31 not in (2, 3)]
    flags_none = [f for f in range(256) if f & 31 == 2]
    flags_single = [f for f in range(256) if f & 31 == 3]
    assert (len(flags_all), len(flags_none), len(flags_single)) == (240, 8, 8)
    # All 512 cases really evaluate both curve equations. These alpha values
    # are fixed r=s=1 DER signatures, not claimed hashes of known preimages.
    nonce = lift(1)
    assert nonce is not None and lift(1 + ec.N) is None
    counts = []
    for index in (0, 1):
        accepted = []
        rejected = []
        for flag in range(256):
            ds = [digest(inputs, outputs, index, code, flag)
                  for code in (sighash.clean(FRAGMENT), bytes.fromhex("ac91"))]
            zs = [int.from_bytes(d, "big") % ec.N for d in ds]
            point = recovery(1, 1, zs[0], nonce)
            first = ec.verify(zs[0], 1, 1, point)[0]
            second = ec.verify(zs[1], 1, 1, point)[0]
            assert first
            passes = first and not second
            assert passes == (index == 0 or flag & 31 != 3)
            (accepted if passes else rejected).append(flag)
        counts.append({"input_index": index, "output_count": 1,
                       "accepted_count": len(accepted), "rejected_flags": rejected,
                       "none_flags_accepted": [f for f in flags_none if f in accepted]})
    # Complete hash-root wrapper algebra with the known public NONE preimage.
    r, s, flag = parse(ALPHA)
    branches = [(x, lift(x)) for x in (r, r + ec.N) if x < ec.P]
    roots = [point for _, point in branches if point is not None]
    assert flag == 2 and lift(r) is None and len(roots) == 1
    changed = [(7000, b"\x51"), (2999, bytes.fromhex("0014") + b"\x22" * 20)]
    wrapper_codes = (sighash.clean(WRAPPER), bytes.fromhex("ac91"))
    rows = []
    q = None
    for name, outs in (("intended", outputs), ("changed_amount_script_and_count", changed)):
        ds = [digest(inputs, outs, 0, code, flag) for code in wrapper_codes]
        zs = [int.from_bytes(d, "big") % ec.N for d in ds]
        if q is None:
            q = recovery(r, s, zs[0], roots[0])
        checks = [ec.verify(z, r, s, q)[0] for z in zs]
        assert checks == [True, False]
        rows.append({"name": name, "digests": [d.hex() for d in ds],
                     "ecdsa_checks": checks, "guard_accepts": True})
    assert rows[0]["digests"] == rows[1]["digests"]
    # Fixed r=s=1 ALL companion: confirm its exact residual equation and the
    # absence of an automatic flag check for this representative root tuple.
    companions = []
    z_all = int.from_bytes(digest(inputs, outputs, 0, b"\xac", 1), "big") % ec.N
    for f in (0, 1, 2, 3, 4, 0x81, 0x82, 0x83):
        z_f = int.from_bytes(digest(inputs, outputs, 0, b"\xac", f), "big") % ec.N
        point = recovery(r, s, z_f, roots[0])
        # P=(sR-z_f G)/r always holds. A fixed-ALL companion requires
        # z_all G+P to equal either nonce point of r0=s0=1.
        right = ec.mul(z_f - r * z_all)
        branch_equations = []
        for fixed_nonce in (nonce, (nonce[0], ec.P - nonce[1])):
            left = ec.add(ec.mul(s, roots[0]), ec.mul(-r, fixed_nonce))
            branch_equations.append(left == right)
        companion_ok = ec.verify(z_all, 1, 1, point)[0]
        assert any(branch_equations) == companion_ok
        assert not companion_ok
        companions.append({"flag": f, "hash_preimage_known_for_this_alpha": f == 2,
                           "fixed_all_companion_accepts": companion_ok,
                           "fixed_nonce_branch_equations_hold": branch_equations,
                           "residual_equation_checked": True})
    # The exact-copy degenerate identity does pass; it is a 9-byte signature,
    # and therefore cannot itself be a 20- or 32-byte native hash output.
    p_fixed = recovery(1, 1, z_all, nonce)
    assert ec.verify(z_all, 1, 1, p_fixed)[0]
    return {
        "question": "Can native checks force a variable hash-derived ECDSA signature to commit all outputs?",
        "evidence": "locally-reproduced", "deployment_class": "unclassified",
        "boundary": "Host serialization and secp256k1 equations only; no Bitcoin Script execution and no complete covenant.",
        "core_revision": sighash.CORE,
        "all_assertions_passed": True,
        "all_output_flag_count": 240, "none_flags": flags_none, "single_flags": flags_single,
        "honest_all_output_flag_fraction": "15/16",
        "extra_honest_flag_bits_for_full_outputs": math.log2(16 / 15),
        "all_synthetic_flags_tested": 256, "synthetic_curve_cases": 512,
        "single_bug_guard": {"fragment_hex": FRAGMENT.hex(), "fragment_bytes": len(FRAGMENT),
                             "static_counted_opcodes": 5, "complete_entry_data_items": 2,
                             "hint_items": 0, "combined_stack_peak_by_inspection": 4,
                             "hash_wrapper_hex": WRAPPER.hex(), "hash_wrapper_bytes": len(WRAPPER),
                             "hash_wrapper_static_counted_opcodes": 8,
                             "hash_wrapper_entry_data_items": 2, "hash_wrapper_hint_items": 0,
                             "hash_wrapper_combined_stack_peak_by_inspection": 4,
                             "script_sig_bytes": None, "serialized_witness_bytes": None,
                             "serialization_note": "No complete transaction; not measured witness or scriptSig bytes.",
                             "flag_results": counts},
        "known_none_hash_root": {"preimage": PREIMAGE.hex(), "alpha": ALPHA.hex(),
                                 "r": str(r), "s": str(s), "flag": flag,
                                 "x_r_lifts": lift(r) is not None, "x_r_plus_n_lifts": lift(r + ec.N) is not None,
                                 "same_public_key": ser(q).hex(), "variants": rows},
        "fixed_all_companion": {"synthetic_flags": companions,
                                "degenerate_equal_r_s_one_signature_length": 9,
                                "degenerate_equal_signature_accepts": True},
        "scope": "Guard exactly rejects the out-of-range SINGLE constant; it is not a NONE/SINGLE-in-range flag filter. Companion checks impose a group equation, not merely a flag predicate.",
    }


if __name__ == "__main__":
    result = run()
    Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
