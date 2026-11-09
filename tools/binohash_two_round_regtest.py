#!/usr/bin/env python3
"""Validate two reduced FindAndDelete rounds in one funded legacy P2SH spend."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from binohash_core_regtest import consensus_probe, decoded_matches
from core_regtest import RELEASE, ROOT, START_TIME, Node, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_two_round_subsets"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000
CONTROLS = ("flip_first", "flip_second", "wrong_size")


def generate(funding_txid, destination):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination], cwd=ROOT)
    return json.loads(raw)


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
    if (template["experiment"] != "binohash-two-round-subsets" or
            template["funding_txid"] != ZERO_TXID or
            template["target_puzzle_signature_bytes"] != 71 or
            template["selected_indices"][0] == template["selected_indices"][1] or
            template["redeem_script_bytes"] > 520):
        raise RuntimeError("Two-round template changed")
    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    easy = bytes.fromhex(template["easy_script_pubkey_hex"])
    locking = bytes.fromhex(template["locking_script_hex"])
    for attempt in range(128):
        outputs = [(INPUT_VALUE, easy), (INPUT_VALUE, locking),
                   (5_000_000_000 - 2 * INPUT_VALUE - FUNDING_FEE - attempt,
                    bytes.fromhex(destination))]
        funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
        fixture = generate(funding["txid"], destination)
        if (fixture["locking_script_hex"] == template["locking_script_hex"] and
                fixture["selected_pool_variant"] == template["selected_pool_variant"]):
            break
    else:
        raise RuntimeError("No deterministic funding txid preserved the two-round script")
    report["funding_search_attempt"] = attempt
    report["funding_transaction"] = funding
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_block_hash"] = block
    report["fixture"] = fixture
    report["controls"] = {}
    for name in CONTROLS:
        tx = fixture["transactions"][name]
        decoded = decoded_matches(node, tx)
        consensus = consensus_probe(node, address, tx, False)
        expected = ("Script failed an OP_EQUALVERIFY operation" if name == "wrong_size"
                    else "Script failed an OP_CHECKMULTISIGVERIFY operation")
        prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                  f"({expected}), input 1 of {tx['txid']}")
        if consensus.get("rpc_code") != -25 or not consensus.get("reason", "").startswith(prefix):
            raise RuntimeError(f"Unexpected Core rejection for {name}: {consensus}")
        report["controls"][name] = {"decoded": decoded, "consensus": consensus}
    valid = fixture["transactions"]["valid"]
    report["valid_decoded"] = decoded_matches(node, valid)
    report["valid_policy"] = node.rpc("testmempoolaccept", [valid["hex"]])[0]
    report["valid_consensus"] = consensus_probe(node, address, valid, True)


def report_passed(report):
    try:
        f = report["fixture"]
        valid = f["transactions"]["valid"]
        if ("infrastructure_error" in report or report["schema_version"] != 1 or
                report["experiment"] != "funded-binohash-two-round-subsets" or
                report["bitcoin_core"]["commit"] != RELEASE["commit"] or
                report["funding_search_attempt"] != 91 or
                [report["funding_transaction"][k] for k in
                 ("base_bytes", "total_bytes", "weight", "vsize")] != [158, 163, 637, 160] or
                f["funding_txid"] != report["funding_transaction"]["txid"] or
                f["target_puzzle_signature_bytes"] != 71 or
                f["selected_indices"] != [0, 1] or
                f["round_candidate_counts"] != [1, 2] or
                f["round_candidate_counts"] != [len(rows) for rows in f["round_candidates"]] or
                f["selected_pool_variant"] != 11 or f["pool_variant_attempts"] != 12 or
                f["redeem_script_bytes"] != len(bytes.fromhex(f["redeem_script_hex"])) or
                f["redeem_script_bytes"] != 454 or f["locking_script_bytes"] != 23 or
                f["hint_items"] != 0 or f["witness_items"] != 0 or
                len(f["pool_signatures_hex"]) != 4 or
                any(s[-2:] != "03" for s in f["pool_signatures_hex"]) or
                [len(bytes.fromhex(s)) for s in f["selected_puzzle_signatures_hex"]] != [71, 71] or
                f["wrong_size_signature_bytes"] != 72 or
                [valid[k] for k in ("base_bytes", "total_bytes", "weight", "vsize")] != [744, 744, 2976, 744] or
                valid["input_script_sig_bytes"] != [2, 605] or
                report["valid_decoded"]["txid"] != valid["txid"] or
                report["valid_decoded"]["weight"] != valid["weight"] or
                report["valid_decoded"]["size"] != valid["total_bytes"] or
                report["valid_policy"]["allowed"] is not False or
                report["valid_policy"]["reject-reason"] != "mempool-script-verify-flag-failed (Signature is found in scriptCode)" or
                report["valid_consensus"]["accepted"] is not True or
                report["valid_consensus"]["block_height"] != 103 or
                set(report["controls"]) != set(CONTROLS)):
            return False
        for round, choice in enumerate(f["selected_indices"]):
            candidates = f["round_candidates"][round]
            if (not candidates[-1]["passes_size"] or candidates[-1]["choice"] != choice or
                    len(bytes.fromhex(f["selected_puzzle_signatures_hex"][round])) != 71 or
                    f["selected_digests_hex"][round] != candidates[-1]["digest_hex"]):
                return False
        for name in CONTROLS:
            tx = f["transactions"][name]
            row = report["controls"][name]
            expected = ("Script failed an OP_EQUALVERIFY operation" if name == "wrong_size"
                        else "Script failed an OP_CHECKMULTISIGVERIFY operation")
            prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                      f"({expected}), input 1 of {tx['txid']}")
            if (row["decoded"]["txid"] != tx["txid"] or
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
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-two-round-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-two-round-subsets",
              "initial_mocktime": START_TIME,
              "scope": "Two reduced one-of-two FindAndDelete signature pools with distinct selected indices in one funded P2SH spend; no full Binohash security, pinning, or two-round work claim."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-two-round-") as directory:
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
