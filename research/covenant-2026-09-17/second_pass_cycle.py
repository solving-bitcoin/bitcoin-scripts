#!/usr/bin/env python3
"""Public ECDSA equations for a fixed eight-key cycle, plus isolated Core checks.

This is an exact raw consensus-boundary vector, not a library generator or a
covenant. All scalars are public fixtures; no wallet or network peers are used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import tempfile

from core_gate_check import isolated_core_binary, p2sh, push
from core_regtest import Node, consensus_check, transaction
from legacy_same_signature_counterexample import G, N, hash256, mul, signature_integer, verify
from second_pass_structure import raw_tx, serialize

# Initial stack: P0 ... P7 sigma0 ... sigma7. Each edge copies its signature
# twice and checks it under adjacent keys, in two CODESEPARATOR contexts.
# The first copy has SIZE <=60 checked. Eight 2DROPs clean the original pool.
SCRIPT = bytes.fromhex(
    "577982013ca1696079adab57795f79adab567982013ca1695f79adab56795e79adab"
    "557982013ca1695e79adab55795d79adab547982013ca1695d79adab54795c79adab"
    "537982013ca1695c79adab53795b79adab527982013ca1695b79adab52795a79adab"
    "517982013ca1695a79adab51795979adab007982013ca1695979adab00796079adab"
    "6d6d6d6d6d6d6d6d51"
)
assert len(SCRIPT) == 145
TAU = [1] + [-1] * 7  # Product -1, so the cycle closes by division by two.
K = pow(2, -1, N)
R = mul(K)
R_SCALAR = R[0] % N


def script_codes():
    # Every push in this exact vector has at most one data byte. No signature
    # (59/60 bytes) can be an opcode-boundary FindAndDelete match.
    boundaries, start, pc, counted = [], 0, 0, 0
    while pc < len(SCRIPT):
        opcode = SCRIPT[pc]
        pc += 1
        if 1 <= opcode <= 75:
            pc += opcode
        elif opcode > 0x60:
            counted += 1
        if opcode == 0xad:
            boundaries.append(start)
        if opcode == 0xab:
            start = pc
    assert len(boundaries) == 16 and counted == 96
    # No data byte equals CODESEPARATOR in this particular raw vector.
    return [SCRIPT[start:].replace(b"\xab", b"") for start in boundaries]


def solution(txid, output_script):
    outputs = [(990000, output_script)]
    codes = script_codes()
    digests = [hash256(raw_tx([(txid, 0, code)], outputs) + struct.pack("<I", 1)) for code in codes]
    zs = [int.from_bytes(digest, "big") % N for digest in digests]
    inv_r = pow(R_SCALAR, -1, N)
    offset = 0
    for i, tau in enumerate(TAU):
        offset = (tau * offset + (tau * zs[2*i] - zs[2*i+1]) * inv_r) % N
    d0 = offset * pow(2, -1, N) % N
    scalars, signature_scalars = [d0], []
    for i, tau in enumerate(TAU):
        d = scalars[-1]
        s = (zs[2*i] + R_SCALAR * d) * pow(K, -1, N) % N
        signature_scalars.append(min(s, N-s))
        scalars.append((tau * d + (tau * zs[2*i] - zs[2*i+1]) * inv_r) % N)
    assert scalars[-1] == d0 and all(scalars) and all(signature_scalars)
    points = [mul(d) for d in scalars[:-1]]
    pubkeys = [bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big") for point in points]
    signatures, equations = [], []
    for i, s in enumerate(signature_scalars):
        body = signature_integer(R_SCALAR) + signature_integer(s)
        signatures.append(b"\x30" + bytes([len(body)]) + body + b"\x01")
        assert len(signatures[-1]) <= 60
        left = verify(zs[2*i], R_SCALAR, s, points[i])
        right = verify(zs[2*i+1], R_SCALAR, s, points[(i+1) % 8])
        assert left[0] and right[0]
        observed_tau = 1 if left[1] == right[1] else -1
        assert observed_tau == TAU[i]
        equations.append({"left_valid": left[0], "right_valid": right[0], "relative_nonce_sign": observed_tau})
    entry = pubkeys + signatures
    sig_script = b"".join(push(item) for item in entry) + push(SCRIPT)
    spend = serialize([(txid, 0, sig_script)], outputs)
    return spend, {
        "digest_hex": [digest.hex() for digest in digests],
        "script_codes": [code.hex() for code in codes],
        "public_scalars_hex": [f"{d:064x}" for d in scalars[:-1]],
        "public_keys_hex": [key.hex() for key in pubkeys],
        "signatures_hex": [signature.hex() for signature in signatures],
        "signature_bytes": [len(signature) for signature in signatures],
        "equations": equations,
        "search_trials": 0,
        "hint_items": 0,
        "redeem_entry_data_items": 16,
        "script_sig_push_items": 17,
        "script_sig_bytes": len(sig_script),
        "combined_stack_peak_by_inspection": 19,
        "redeem_executed_non_push_opcodes": 96,
        "complete_executed_non_push_opcodes": 98,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path("/private/tmp/covenant-core-30.3"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    binary, provenance = isolated_core_binary(args.cache_dir, False)
    report = {"question": "Does an even ECDSA key cycle necessarily impose a hard relation among its transaction digests?",
              "answer": False, "bitcoin_core": provenance,
              "scope": "Fixed raw P2SH cycle with freely supplied public keys; every honest fixture uses r=x(G/2).",
              "redeemscript_hex": SCRIPT.hex(), "redeemscript_bytes": len(SCRIPT),
              "locking_script_bytes": 23, "relative_signs": TAU,
              "known_nonce_scalar_hex": f"{K:064x}", "r_hex": f"{R_SCALAR:x}", "results": []}
    with tempfile.TemporaryDirectory(prefix="covenant-public-cycle-") as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc("decodescript", "51")["segwit"]["address"]
            mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
            hashes = []
            for _ in range(101):
                node.tick()
                hashes += node.rpc("generatetoaddress", 1, address)
            cb = node.rpc("getblock", hashes[0], 2)["tx"][0]
            coin = next(o for o in cb["vout"] if o["scriptPubKey"]["hex"] == mining_script.hex())
            funding = transaction(cb["txid"], coin["n"], [b"\x51"],
                                  [(1000000, p2sh(SCRIPT)), (4998990000, mining_script)])
            assert node.rpc("sendrawtransaction", funding["hex"]) == funding["txid"]
            node.tick()
            node.rpc("generatetoaddress", 1, address)
            report["funding_txid"] = funding["txid"]
            for recipient in [0x11, 0x22]:
                output_script = b"\x00\x14" + bytes([recipient]) * 20
                spend, model = solution(funding["txid"], output_script)
                decoded = node.rpc("decoderawtransaction", spend["hex"])
                assert decoded["txid"] == spend["txid"] and decoded["weight"] == spend["weight"]
                policy = node.rpc("testmempoolaccept", [spend["hex"]])[0]
                result = consensus_check(node, address, spend)
                assert result["accepted"] and not policy["allowed"]
                report["results"].append({"recipient_script": output_script.hex(), "model": model,
                    "transaction": spend, "consensus": result, "policy": policy,
                    "evidence": "differentially-validated", "deployment_class": "consensus-validated"})
                print(f"PASS public cycle recipient={recipient:02x}: 16 native checks accepted, zero search trials")
                node.rpc("invalidateblock", result["block_hash"])
            report["all_expectations_met"] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
