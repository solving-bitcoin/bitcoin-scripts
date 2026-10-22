#!/usr/bin/env python3
"""Reduced 2-of-3 legacy subset and Script-consumer comparison with Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from binohash_core_regtest import (POLICY_REJECTION, consensus_probe,
                                   decoded_matches)
from core_regtest import (RELEASE, ROOT, START_TIME, Node, core_binary,
                          transaction)
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_subset_fixtures"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000
CONTROLS = ("wrong_preimage", "wrong_indices", "reversed_indices",
            "duplicate_indices", "out_of_range_index", "noncanonical_index",
            "wrong_size")
CONSENSUS_PREFIX = "TestBlockValidity failed: block-script-verify-flag-failed ("
REJECTIONS = {
    "wrong_preimage": "Script evaluated without error but finished with a false/empty top stack element",
    "wrong_indices": "Script failed an OP_CHECKMULTISIGVERIFY operation",
    "reversed_indices": "Script failed an OP_VERIFY operation",
    "duplicate_indices": "Script failed an OP_VERIFY operation",
    "out_of_range_index": "Script failed an OP_VERIFY operation",
    "noncanonical_index": "Script failed an OP_VERIFY operation",
    "wrong_size": "Script failed an OP_VERIFY operation",
}


def rejection_matches(control, name, txid):
    return (control.get("accepted") is False and control.get("rpc_code") == -25 and
            control.get("reason", "").startswith(
                CONSENSUS_PREFIX + REJECTIONS[name] + "), input 1 of " + txid))


def generate(funding_txid, destination_script, easy_vout=0, bino_vout=1):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script, str(easy_vout), str(bino_vout)],
        cwd=ROOT)
    return json.loads(raw)


def static_shape_matches(base, funded):
    keys = ("experiment", "input_value_sat", "fee_sat", "max_puzzle_signature_bytes",
            "redeem_script_hex", "redeem_script_bytes", "binohash_script_pubkey_hex",
            "easy_script_pubkey_hex", "destination_script_pubkey_hex",
            "pool_signatures_hex", "preimage_hashes_hex")
    return all(base[key] == funded[key] for key in keys)


def run(node, report):
    csv_manifest, _ = csv_generate()
    if (csv_manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
            csv_manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]):
        raise RuntimeError("Pinned mining-address source changed Core version")
    address = csv_manifest["mining_address"]
    destination_script = node.rpc("validateaddress", address)["scriptPubKey"]
    if destination_script != csv_manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and mining-address generator disagree")
    report["mining_address"] = address
    report["destination_script_pubkey_hex"] = destination_script
    base = generate(ZERO_TXID, destination_script)
    if (base["experiment"] != "binohash-legacy-2-of-3-toy" or
            base["funding_txid"] != ZERO_TXID or
            base["input_value_sat"] != INPUT_VALUE or
            base["max_puzzle_signature_bytes"] != 71 or
            base["redeem_script_bytes"] > 520 or len(base["results"]) != 3):
        raise RuntimeError("Toy subset manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination_script)
    easy = bytes.fromhex(base["easy_script_pubkey_hex"])
    bino = bytes.fromhex(base["binohash_script_pubkey_hex"])
    for attempt in range(64):
        outputs = [(INPUT_VALUE, easy), (INPUT_VALUE, bino),
                   (INPUT_VALUE, easy), (INPUT_VALUE, bino),
                   (5_000_000_000 - 4 * INPUT_VALUE - FUNDING_FEE - attempt,
                    bytes.fromhex(destination_script))]
        funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
        first = generate(funding["txid"], destination_script, 0, 1)
        second = generate(funding["txid"], destination_script, 2, 3)
        if not (static_shape_matches(base, first) and
                static_shape_matches(base, second)):
            raise RuntimeError("Funding changed the committed toy redeemScript")
        if (first["results"][0]["passes_size_filter"] and
                second["results"][1]["passes_size_filter"] and
                any(not row["passes_size_filter"] for funded in (first, second)
                    for row in funded["results"])):
            break
    else:
        raise RuntimeError("No deterministic funding fixture exposed both puzzle outcomes")
    report["funding_search_attempt"] = attempt
    report["funding_transaction"] = funding
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_block_hash"] = funding_block
    report["fixture"] = {
        "redeem_script_hex": first["redeem_script_hex"],
        "redeem_script_bytes": first["redeem_script_bytes"],
        "binohash_script_pubkey_hex": first["binohash_script_pubkey_hex"],
        "pool_signatures_hex": first["pool_signatures_hex"],
        "preimage_hashes_hex": first["preimage_hashes_hex"],
        "max_puzzle_signature_bytes": first["max_puzzle_signature_bytes"],
    }
    report["spends"] = []
    for label, funded, selected_index in (("pair-0-1", first, 0),
                                          ("pair-0-2", second, 1)):
        selected = funded["results"][selected_index]
        spend = {
            "name": label,
            "easy_vout": funded["easy_vout"],
            "binohash_vout": funded["binohash_vout"],
            "candidates": [{key: row[key] for key in
                            ("pair", "local_digest_hex", "puzzle_signature_bytes",
                             "passes_size_filter")}
                           for row in funded["results"]],
            "selected_pair": selected["pair"],
            "selected_local_digest_hex": selected["local_digest_hex"],
            "selected_preimage_hex": selected["preimage_hex"],
            "selected_puzzle_signature_hex": selected["puzzle_signature_hex"],
            "oversized_valid_puzzle_signature_hex": selected[
                "oversized_valid_puzzle_signature_hex"],
            "controls": {},
        }
        for name in CONTROLS:
            tx = selected[name]
            decoded = decoded_matches(node, tx)
            consensus = consensus_probe(node, address, tx, False)
            if not rejection_matches(consensus, name, tx["txid"]):
                raise RuntimeError(f"Unexpected consensus rejection for {label} {name}")
            spend["controls"][name] = {"transaction": tx, "decoded": decoded,
                                       "consensus": consensus}
        tx = selected["transaction"]
        decoded = decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if (policy.get("allowed") is not False or
                policy.get("reject-reason") != POLICY_REJECTION):
            raise RuntimeError(f"Unexpected policy result for {label}")
        consensus = consensus_probe(node, address, tx, True)
        spend["valid"] = {"transaction": tx, "decoded": decoded,
                          "policy": policy, "consensus": consensus}
        report["spends"].append(spend)


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-2-of-3-toy" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            len(report.get("spends", [])) != 2 or
            report.get("fixture", {}).get("redeem_script_bytes", 521) > 520):
        return False
    spends = report["spends"]
    if ([(spend["name"], spend["selected_pair"], spend["easy_vout"],
          spend["binohash_vout"]) for spend in spends] !=
            [("pair-0-1", [0, 1], 0, 1), ("pair-0-2", [0, 2], 2, 3)] or
            spends[0]["selected_local_digest_hex"] ==
            spends[1]["selected_local_digest_hex"] or
            spends[0]["selected_preimage_hex"] ==
            spends[1]["selected_preimage_hex"] or
            not any(not row["passes_size_filter"] for spend in spends
                    for row in spend["candidates"])):
        return False
    for spend in spends:
        candidates = spend["candidates"]
        if (set(spend["controls"]) != set(CONTROLS) or len(candidates) != 3 or
                {tuple(row["pair"]) for row in candidates} !=
                {(0, 1), (0, 2), (1, 2)} or
                len({row["local_digest_hex"] for row in candidates}) != 3 or
                spend["selected_pair"] not in
                [row["pair"] for row in candidates if row["passes_size_filter"]] or
                spend["selected_local_digest_hex"] != next(
                    row["local_digest_hex"] for row in candidates
                    if row["pair"] == spend["selected_pair"])):
            return False
        valid = spend["valid"]
        if (valid["consensus"].get("accepted") is not True or
                valid["policy"].get("allowed") is not False or
                valid["policy"].get("reject-reason") != POLICY_REJECTION or
                valid["transaction"]["txid"] != valid["decoded"]["txid"] or
                valid["transaction"]["txid"] != valid["policy"].get("txid")):
            return False
        for name, control in spend["controls"].items():
            if (not rejection_matches(control["consensus"], name,
                                      control["transaction"]["txid"]) or
                    control["transaction"]["txid"] != control["decoded"]["txid"] or
                    control["transaction"]["txid"] == valid["transaction"]["txid"]):
                return False
    if spends[0]["valid"]["transaction"]["txid"] == spends[1]["valid"]["transaction"]["txid"]:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-subset-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-2-of-3-toy",
              "initial_mocktime": START_TIME,
              "scope": "Two disjoint low-work 2-of-3 legacy subset spends with OP_ROLL, size filter, and Script-consuming preimage checks. No transaction pinning, two-round grind, or collision-security claim."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-subset-") as directory:
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
