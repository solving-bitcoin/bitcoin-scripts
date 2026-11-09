#!/usr/bin/env python3
"""Compare an exact DER-size ECDSA nonce grind with pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import RELEASE, ROOT, START_TIME, Node, RPCError, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_der_size_grind"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000


def generate(txid, destination):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", txid, destination], cwd=ROOT)
    return json.loads(raw)


def decode(node, tx):
    row = node.rpc("decoderawtransaction", tx["hex"])
    if (row["txid"] != tx["txid"] or row["hash"] != tx["txid"] or
            row["weight"] != tx["weight"] or row["size"] != tx["total_bytes"] or
            row["vsize"] != tx["vsize"] or tx["base_bytes"] != tx["total_bytes"] or
            tx["weight"] != 4 * tx["base_bytes"] or len(row["vin"]) != 1 or
            len(row["vout"]) != 1 or "txinwitness" in row["vin"][0] or
            len(row["vin"][0]["scriptSig"]["hex"]) // 2 != tx["script_sig_bytes"]):
        raise RuntimeError("Core decode disagrees with complete legacy spend")
    return {"txid": row["txid"], "weight": row["weight"],
            "vsize": row["vsize"], "size": row["size"]}


def probe(node, address, tx, should_accept):
    height = node.rpc("getblockcount")
    try:
        result = node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        if should_accept or node.rpc("getblockcount") != height:
            raise RuntimeError(f"Unexpected block rejection: {error.message}") from error
        return {"accepted": False, "rpc_code": error.code, "reason": error.message}
    if not should_accept:
        raise RuntimeError("Invalid-size or invalid-ECDSA signature entered a block")
    block = node.rpc("getblock", result["hash"])
    if block["height"] != height + 1 or tx["txid"] not in block["tx"]:
        raise RuntimeError("Accepted spend missing from connected block")
    return {"accepted": True, "block_hash": result["hash"], "block_height": block["height"]}


def run(node, report):
    manifest, _ = csv_generate()
    if (manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
            manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]):
        raise RuntimeError("Pinned mining-address source changed Core version")
    address = manifest["mining_address"]
    destination = node.rpc("validateaddress", address)["scriptPubKey"]
    if destination != manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and mining-address generator disagree")
    report["mining_address"] = address
    report["destination_script_pubkey_hex"] = destination
    template = generate(ZERO_TXID, destination)
    if (template["experiment"] != "binohash-der-size-grind" or
            template["funding_txid"] != ZERO_TXID or
            template["target_signature_bytes"] != 70 or
            template["sighash_flag_hex"] != "01" or
            template["seed_hex"] != "5a" * 32):
        raise RuntimeError("DER-size fixture template changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    outputs = [(INPUT_VALUE, bytes.fromhex(template["locking_script_hex"])),
               (5_000_000_000 - INPUT_VALUE - FUNDING_FEE, bytes.fromhex(destination))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    fixture = generate(funding["txid"], destination)
    for key in ("experiment", "input_value_sat", "fee_sat", "sighash_flag_hex",
                "seed_hex", "target_signature_bytes", "max_attempts",
                "redeem_script_hex", "locking_script_hex"):
        if fixture[key] != template[key]:
            raise RuntimeError(f"Funding altered fixed script or search parameters: {key}")
    report["fixture"] = fixture
    report["controls"] = {}
    for name, reason in (("invalid_size", "Script failed an OP_EQUALVERIFY operation"),
                         ("invalid_ecdsa", "Script evaluated without error but finished with a false/empty top stack element")):
        tx = fixture["transactions"][name]
        decoded = decode(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        consensus = probe(node, address, tx, False)
        prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                  f"({reason}), input 0 of {tx['txid']}")
        if (consensus.get("rpc_code") != -25 or not consensus.get("reason", "").startswith(prefix) or
                policy.get("allowed") is not False or policy.get("txid") != tx["txid"]):
            raise RuntimeError(f"Unexpected Core rejection for {name}")
        report["controls"][name] = {"decoded": decoded, "policy": policy,
                                    "consensus": consensus}
    valid = fixture["transactions"]["valid"]
    report["valid_decoded"] = decode(node, valid)
    report["valid_policy"] = node.rpc("testmempoolaccept", [valid["hex"]])[0]
    if report["valid_policy"].get("allowed") is not True:
        raise RuntimeError("Valid exact-size P2SH spend failed default policy")
    report["valid_consensus"] = probe(node, address, valid, True)


def report_passed(report):
    try:
        fixture = report["fixture"]
        valid = fixture["transactions"]["valid"]
        if ("infrastructure_error" in report or report["schema_version"] != 1 or
                report["experiment"] != "funded-binohash-der-size-grind" or
                report["bitcoin_core"]["commit"] != RELEASE["commit"] or
                fixture["seed_hex"] != "5a" * 32 or
                fixture["target_signature_bytes"] != 70 or
                fixture["sighash_flag_hex"] != "01" or
                fixture["hint_items"] != 0 or fixture["witness_items"] != 0 or
                fixture["selected_counter"] != 187 or fixture["attempts"] != 188 or
                fixture["other_counter"] != 0 or fixture["other_signature_bytes"] != 72 or
                fixture["max_attempts"] != 10_000 or
                len(bytes.fromhex(fixture["good_signature_hex"])) != 70 or
                len(bytes.fromhex(fixture["wrong_size_signature_hex"])) != 72 or
                len(bytes.fromhex(fixture["wrong_ecdsa_signature_hex"])) != 70 or
                fixture["good_signature_hex"][-2:] != "01" or
                fixture["locking_script_bytes"] != 23 or
                fixture["redeem_script_bytes"] != 39 or
                fixture["redeem_static_non_push_opcodes"] != 3 or
                fixture["redeem_script_bytes"] != len(bytes.fromhex(fixture["redeem_script_hex"])) or
                fixture["funding_txid"] != report["funding_transaction"]["txid"] or
                report["valid_decoded"]["txid"] != valid["txid"] or
                report["valid_decoded"]["weight"] != valid["weight"] or
                [valid[k] for k in ("base_bytes", "total_bytes", "weight", "vsize", "script_sig_bytes")] != [205, 205, 820, 205, 111] or
                report["valid_policy"]["allowed"] is not True or
                report["valid_policy"]["txid"] != valid["txid"] or
                report["valid_consensus"]["accepted"] is not True or
                report["valid_consensus"]["block_height"] != 103 or
                set(report["controls"]) != {"invalid_size", "invalid_ecdsa"}):
            return False
        for name, reason in (("invalid_size", "Script failed an OP_EQUALVERIFY operation"),
                             ("invalid_ecdsa", "Script evaluated without error but finished with a false/empty top stack element")):
            tx = fixture["transactions"][name]
            row = report["controls"][name]
            prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                      f"({reason}), input 0 of {tx['txid']}")
            if (row["decoded"]["txid"] != tx["txid"] or
                    row["decoded"]["weight"] != tx["weight"] or
                    row["policy"]["allowed"] is not False or
                    row["policy"]["txid"] != tx["txid"] or
                    row["consensus"]["accepted"] is not False or
                    row["consensus"]["rpc_code"] != -25 or
                    not row["consensus"]["reason"].startswith(prefix)):
                return False
        return True
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-der-size-grind-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-der-size-grind",
              "initial_mocktime": START_TIME,
              "scope": "One fixed-digest legacy P2SH ECDSA nonce search for a 70-byte signature, with non-target-size and same-size-invalid-ECDSA controls; no full Binohash work or security claim."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-der-") as directory:
            node = Node(binary, Path(directory))
            try:
                node.ready()
                report["node_options"] = node.options
                run(node, report)
            finally:
                node.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    report["run_passed"] = report_passed(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if report["run_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
