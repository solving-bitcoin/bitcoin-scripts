#!/usr/bin/env python3
"""Check signed six-mode legacy sighash field mutations against pinned Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (RELEASE, ROOT, START_TIME, Node, RPCError, core_binary,
                          transaction)
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_signed_sighash_matrix"
ZERO_TXID = "00" * 32
INPUT_VALUE = 100_000
FUNDING_FEE = 50_000
MODES = [1, 2, 3, 129, 130, 131]
MUTATIONS = ["version", "locktime", "selected prevout", "selected sequence",
             "other prevout", "other sequence", "selected output", "other output"]
EXPECTED = [
    [True] * 6, [True] * 6, [True] * 6, [True] * 6,
    [True, True, True, False, False, False],
    [True, False, False, False, False, False],
    [True, False, True, True, False, True],
    [True, False, False, True, False, False],
]
CONSENSUS_REJECTION = ("TestBlockValidity failed: block-script-verify-flag-failed "
                       "(Script evaluated without error but finished with a false/empty top "
                       "stack element), input 1 of ")


def generate(funding_txid, destination_script):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if (tx["base_bytes"] != tx["total_bytes"] or
            tx["weight"] != 4 * tx["base_bytes"] or
            tx["txid"] != decoded["txid"] or
            tx["weight"] != decoded["weight"] or
            tx["total_bytes"] != decoded["size"] or
            len(decoded["vin"]) != 2 or len(decoded["vout"]) != 2 or
            [len(item["scriptSig"]["hex"]) // 2 for item in decoded["vin"]] !=
            tx["script_sig_bytes"] or
            any("txinwitness" in item for item in decoded["vin"])):
        raise RuntimeError("Rust and Core disagree on legacy transaction serialization")


def run(node, report):
    csv_manifest, _ = csv_generate()
    if (csv_manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
            csv_manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]):
        raise RuntimeError("Pinned mining-address source changed Core version")
    address = csv_manifest["mining_address"]
    destination = node.rpc("validateaddress", address)["scriptPubKey"]
    if destination != csv_manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and mining-address generator disagree")
    report["mining_address"] = address
    report["destination_script_pubkey_hex"] = destination
    template = generate(ZERO_TXID, destination)
    if (template["experiment"] != "binohash-signed-six-mode-field-matrix" or
            template["funding_txid"] != ZERO_TXID or
            template["input_value_sat"] != INPUT_VALUE or
            [row["flag"] for row in template["rows"]] != MODES):
        raise RuntimeError("Signed matrix template changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    selected = bytes.fromhex(template["selected_script_pubkey_hex"])
    other = bytes.fromhex(template["other_script_pubkey_hex"])
    outputs = []
    for _ in MODES:
        # Other, selected, other alias, selected alias. All four are funded,
        # so a prevout mutation tests the signature rather than a missing coin.
        outputs.extend([(INPUT_VALUE, other), (INPUT_VALUE, selected),
                        (INPUT_VALUE, other), (INPUT_VALUE, selected)])
    outputs.append((5_000_000_000 - 24 * INPUT_VALUE - FUNDING_FEE,
                    bytes.fromhex(destination)))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination)
    for key in ("experiment", "input_value_sat", "redeem_script_hex",
                "redeem_script_bytes", "selected_script_pubkey_hex",
                "other_redeem_script_hex", "other_script_pubkey_hex",
                "destination_script_pubkey_hex"):
        if funded[key] != template[key]:
            raise RuntimeError(f"Funding changed fixed fixture field: {key}")
    if [row["flag"] for row in funded["rows"]] != MODES:
        raise RuntimeError("Funded matrix modes changed")
    report["fixture"] = {key: funded[key] for key in
                         ("input_value_sat", "redeem_script_hex",
                          "redeem_script_bytes", "selected_script_pubkey_hex",
                          "other_redeem_script_hex", "other_script_pubkey_hex")}
    report["rows"] = []
    accepted_transactions = []
    for mode_index, row in enumerate(funded["rows"]):
        baseline = row["baseline"]
        decoded_matches(node, baseline)
        baseline_policy = node.rpc("testmempoolaccept", [baseline["hex"]])[0]
        if baseline_policy.get("allowed") is not True or baseline_policy.get("txid") != baseline["txid"]:
            raise RuntimeError(f"Baseline policy rejected {row['mode']}: {baseline_policy}")
        variants = []
        if [variant["mutation"] for variant in row["variants"]] != MUTATIONS:
            raise RuntimeError("Mutation order changed")
        for case, variant in enumerate(row["variants"]):
            tx = variant["transaction"]
            decoded_matches(node, tx)
            changed = EXPECTED[case][mode_index]
            if (variant["expected_digest_change"] is not changed or
                    variant["digest_changed"] is not changed or
                    (variant["local_digest_hex"] != row["local_digest_hex"]) is not changed or
                    tx["txid"] == baseline["txid"]):
                raise RuntimeError(f"Digest fixture changed: {row['mode']} {variant['mutation']}")
            policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
            if (policy.get("allowed") is changed or policy.get("txid") != tx["txid"]):
                raise RuntimeError(f"Unexpected policy verdict: {row['mode']} {variant['mutation']}: {policy}")
            consensus = None
            if changed:
                height = node.rpc("getblockcount")
                try:
                    node.rpc("generateblock", address, [tx["hex"]])
                except RPCError as error:
                    if (error.code != -25 or
                            not error.message.startswith(CONSENSUS_REJECTION + tx["txid"]) or
                            node.rpc("getblockcount") != height):
                        raise RuntimeError(f"Unexpected consensus rejection: {error.message}") from error
                    consensus = {"accepted": False, "rpc_code": error.code,
                                 "reason": error.message}
                else:
                    raise RuntimeError(f"Invalid signature entered a block: {row['mode']} {variant['mutation']}")
            variants.append({**variant, "policy": policy, "consensus": consensus})
        report["rows"].append({**row, "baseline_policy": baseline_policy,
                               "variants": variants})
        accepted_transactions.append(baseline["hex"])
    height = node.rpc("getblockcount")
    block_hash = node.rpc("generateblock", address, accepted_transactions)["hash"]
    block = node.rpc("getblock", block_hash)
    txids = {row["baseline"]["txid"] for row in funded["rows"]}
    if (block["height"] != height + 1 or
            not txids.issubset(set(block["tx"])) or len(txids) != 6):
        raise RuntimeError("Core did not confirm six signed baselines")
    report["baseline_consensus"] = {"accepted": True, "block_hash": block_hash,
                                    "block_height": block["height"],
                                    "confirmed_txids": len(txids)}


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-signed-six-mode-field-matrix" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            report.get("fixture", {}).get("redeem_script_bytes") != 35 or
            report.get("fixture", {}).get("other_redeem_script_hex") != "51" or
            report.get("baseline_consensus", {}).get("accepted") is not True or
            report.get("baseline_consensus", {}).get("confirmed_txids") != 6 or
            len(report.get("rows", [])) != 6):
        return False
    for mode_index, row in enumerate(report["rows"]):
        baseline = row.get("baseline", {})
        if (row.get("flag") != MODES[mode_index] or
                row.get("baseline_policy", {}).get("allowed") is not True or
                row["baseline_policy"].get("txid") != baseline.get("txid") or
                len(row.get("variants", [])) != 8):
            return False
        for case, variant in enumerate(row["variants"]):
            tx = variant.get("transaction", {})
            changed = EXPECTED[case][mode_index]
            if (variant.get("mutation") != MUTATIONS[case] or
                    variant.get("expected_digest_change") is not changed or
                    variant.get("digest_changed") is not changed or
                    (variant.get("local_digest_hex") != row.get("local_digest_hex")) is not changed or
                    tx.get("txid") == baseline.get("txid") or
                    variant.get("policy", {}).get("allowed") is changed or
                    variant["policy"].get("txid") != tx.get("txid")):
                return False
            consensus = variant.get("consensus")
            if changed:
                if (not isinstance(consensus, dict) or
                        consensus.get("accepted") is not False or
                        consensus.get("rpc_code") != -25 or
                        not consensus.get("reason", "").startswith(
                            CONSENSUS_REJECTION + tx.get("txid", ""))):
                    return False
            elif consensus is not None:
                return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-signed-sighash-matrix-v30.3.json")
    args = parser.parse_args()
    report = {
        "schema_version": 1,
        "experiment": "funded-binohash-signed-six-mode-field-matrix",
        "initial_mocktime": START_TIME,
        "scope": "Six signed, two-input legacy P2SH baselines and 48 single-field variants. Core mines all baselines, rejects changed-digest variants by generateblock, and tests every variant under default relay policy. Unchanged-digest variants have policy verdicts only. No embedded-signature FindAndDelete grind, pinning or security bound.",
    }
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-signed-matrix-") as directory:
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
