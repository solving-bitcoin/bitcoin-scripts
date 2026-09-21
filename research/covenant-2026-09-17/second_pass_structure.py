#!/usr/bin/env python3
"""Concrete Core checks for scriptSig-budget and SINGLE-bug composition ideas.

Only a fresh, isolated regtest chain is used. These are raw consensus-boundary
vectors, not optimized repository primitives or a proposed covenant.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import tempfile

from core_gate_check import isolated_core_binary, p2sh, push
from core_regtest import Node, compact_size, consensus_check, transaction, vector
from legacy_same_signature_counterexample import G, N, hash256, signature_integer, verify


PUBLIC_KEY = b"\x02" + G[0].to_bytes(32, "big")
# 199 NOPs, CHECKSIGVERIFY, VERIFY: exactly 201 counted opcodes.
LOCK = b"\x61" * 199 + push(PUBLIC_KEY) + b"\xad\x69\x51"
COMPUTATION = b"\x51" + b"\x91" * 200  # TRUE followed by 200 NOTs = TRUE.


def raw_tx(inputs, outputs):
    raw = struct.pack("<I", 2) + compact_size(len(inputs))
    for txid, vout, script_sig in inputs:
        raw += bytes.fromhex(txid)[::-1] + struct.pack("<I", vout) + vector(script_sig) + b"\xff" * 4
    raw += compact_size(len(outputs))
    for value, script in outputs:
        raw += struct.pack("<Q", value) + vector(script)
    return raw + b"\0" * 4


def serialize(inputs, outputs):
    raw = raw_tx(inputs, outputs)
    return {"hex": raw.hex(), "txid": hash256(raw)[::-1].hex(),
            "total_bytes": len(raw), "weight": 4 * len(raw), "witness_bytes": 0}


def sign_digest(digest, flag):
    # Public d=k=1; normalized low-S. This is intentionally no deleted-key setup.
    z = int.from_bytes(digest, "big")
    r = G[0] % N
    s = (z + r) % N
    s = min(s, N - s)
    assert verify(z, r, s, G)[0]
    body = signature_integer(r) + signature_integer(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([flag])


def sign_all(txid, vout, outputs):
    digest = hash256(raw_tx([(txid, vout, LOCK)], outputs) + struct.pack("<I", 1))
    return sign_digest(digest, 1), digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path("/private/tmp/covenant-core-30.3"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    binary, provenance = isolated_core_binary(args.cache_dir, False)

    # uint256::ONE is 01 00...00 in the byte array handed to ECDSA, hence z=2^248.
    bug_digest = b"\x01" + b"\x00" * 31
    bug_sig = sign_digest(bug_digest, 3)
    bug_lock = push(bug_sig) + push(PUBLIC_KEY) + b"\xac"
    funding_scripts = [LOCK, p2sh(LOCK), bug_lock, b"\x51", b"\x52\x75\x51"]
    recipient_a = b"\x00\x14" + b"\x11" * 20
    recipient_b = b"\x00\x14" + b"\x22" * 20
    report = {
        "question": "Can extra scriptSig execution or SINGLE-bug-required inputs carry authenticated extra verification?",
        "bitcoin_core": provenance,
        "scope": "Complete isolated Core regtest transactions. No covenant or new PoW search.",
        "locking_script_hex": LOCK.hex(), "locking_script_bytes": len(LOCK),
        "locking_script_static_non_push_opcodes": 201,
        "script_sig_computation_hex": COMPUTATION.hex(),
        "script_sig_computation_non_push_opcodes": 200,
        "single_bug_digest_bytes": bug_digest.hex(),
        "single_bug_ecdsa_z_hex": f"{int.from_bytes(bug_digest, 'big'):064x}",
        "single_bug_signature": bug_sig.hex(), "single_bug_script_hex": bug_lock.hex(),
        "hint_items": 0, "results": [],
    }
    with tempfile.TemporaryDirectory(prefix="covenant-structure-") as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc("decodescript", "51")["segwit"]["address"]
            mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
            hashes = []
            for _ in range(101):
                node.tick()
                hashes += node.rpc("generatetoaddress", 1, address)
            coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
            coin = next(o for o in coinbase["vout"] if o["scriptPubKey"]["hex"] == mining_script.hex())
            funding_outputs = [(1_000_000, script) for script in funding_scripts]
            funding_outputs += [(5_000_000_000 - len(funding_scripts) * 1_000_000 - 10_000, mining_script)]
            funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], funding_outputs)
            funded = consensus_check(node, address, funding)
            assert funded["accepted"], funded
            txid = funding["txid"]
            report["funding"] = funding

            def check(name, inputs, outputs, expected, **details):
                spend = serialize(inputs, outputs)
                decoded = node.rpc("decoderawtransaction", spend["hex"])
                assert decoded["txid"] == spend["txid"] and decoded["weight"] == spend["weight"]
                policy = node.rpc("testmempoolaccept", [spend["hex"]])[0]
                result = consensus_check(node, address, spend)
                assert result["accepted"] == expected, (name, result)
                report["results"].append({
                    "name": name, "transaction": spend, "consensus": result, "policy": policy,
                    "evidence": "differentially-validated",
                    "deployment_class": "consensus-validated" if expected else "consensus-incompatible",
                    "script_sig_bytes": [len(row[2]) for row in inputs],
                    "hint_items": 0, **details,
                })
                print(f"PASS {name}: consensus={expected}, policy={policy['allowed']}")
                if expected:
                    node.rpc("invalidateblock", result["block_hash"])

            good_outputs = [(990_000, recipient_a)]
            bad_outputs = [(990_000, recipient_b)]
            sig, digest = sign_all(txid, 0, good_outputs)
            check("bare-401-ops-split-executions", [(txid, 0, COMPUTATION + push(sig))], good_outputs, True,
                  native_all_signature=sig.hex(), native_all_digest=digest.hex(),
                  executed_non_push_opcodes=401, entry_items_to_fixed_script=2, combined_stack_peak_by_inspection=3)
            check("bare-computation-replaced-by-push", [(txid, 0, b"\x51" + push(sig))], good_outputs, True,
                  native_all_signature=sig.hex(), native_all_digest=digest.hex(),
                  executed_non_push_opcodes=201, entry_items_to_fixed_script=2, combined_stack_peak_by_inspection=3)
            bad_sig, bad_digest = sign_all(txid, 0, bad_outputs)
            check("bare-other-output-public-key-owner-resigns", [(txid, 0, b"\x51" + push(bad_sig))], bad_outputs, True,
                  native_all_signature=bad_sig.hex(), native_all_digest=bad_digest.hex(),
                  executed_non_push_opcodes=201, entry_items_to_fixed_script=2, combined_stack_peak_by_inspection=3)
            p2sh_sig, _ = sign_all(txid, 1, good_outputs)
            check("p2sh-nonpush-script-sig-rejected", [(txid, 1, COMPUTATION + push(p2sh_sig) + push(LOCK))], good_outputs, False,
                  complete_script_sig_stack_items_if_executed=3, combined_stack_peak_by_inspection=4)
            check("p2sh-push-only-endstack-accepted", [(txid, 1, b"\x51" + push(p2sh_sig) + push(LOCK))], good_outputs, True,
                  executed_non_push_opcodes=203, entry_items_to_redeem_script=2, combined_stack_peak_by_inspection=4)

            single_outputs = [(1_990_000, recipient_a)]
            check("single-bug-other-input-A", [(txid, 3, b""), (txid, 2, b"")], single_outputs, True,
                  executed_non_push_opcodes=1, combined_stack_peak_by_inspection=2)
            check("single-bug-other-input-B-different-program", [(txid, 4, b""), (txid, 2, b"")], single_outputs, True,
                  executed_non_push_opcodes=2, combined_stack_peak_by_inspection=2)
            check("single-bug-other-recipient", [(txid, 4, b""), (txid, 2, b"")], [(1_990_000, recipient_b)], True,
                  executed_non_push_opcodes=2, combined_stack_peak_by_inspection=2)
            check("single-bug-target-at-index-zero-rejected", [(txid, 2, b""), (txid, 3, b"")], single_outputs, False,
                  combined_stack_peak_by_inspection=2)
            check("single-bug-two-outputs-rejected", [(txid, 3, b""), (txid, 2, b"")],
                  [(990_000, recipient_a), (1_000_000, recipient_b)], False,
                  combined_stack_peak_by_inspection=2)
            report["all_expectations_met"] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
