#!/usr/bin/env python3
"""Core-check field mutations that retain a legacy SIGHASH_SINGLE bug anchor."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from binohash_core_regtest import POLICY_REJECTION, consensus_probe
from core_regtest import RELEASE, ROOT, START_TIME, Node, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_single_bug_pinning_skip"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000
MUTATIONS = ("version", "locktime", "selected prevout", "selected sequence",
             "other prevout", "other sequence", "output value", "output script",
             "all eight fields")
CONTROLS = {"added_output": 1, "moved_input": 0}
BUG_DIGEST = "01" + "00" * 31
CONSENSUS_REJECTION = ("TestBlockValidity failed: block-script-verify-flag-failed "
                       "(Script evaluated without error but finished with a false/empty top "
                       "stack element), input ")


def generate(funding_txid, destination):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if (tx["base_bytes"] != tx["total_bytes"] or
            tx["weight"] != 4 * tx["base_bytes"] or
            tx["txid"] != decoded["txid"] or
            tx["weight"] != decoded["weight"] or
            tx["total_bytes"] != decoded["size"] or
            len(decoded["vin"]) != 2 or
            len(decoded["vout"]) != tx["output_count"] or
            [item["vout"] for item in decoded["vin"]] != tx["input_vouts"] or
            [len(item["scriptSig"]["hex"]) // 2 for item in decoded["vin"]] !=
            tx["script_sig_bytes"] or
            any("txinwitness" in item for item in decoded["vin"])):
        raise RuntimeError("Core and Rust disagree on legacy transaction serialization")
    return {"txid": decoded["txid"], "weight": decoded["weight"],
            "vsize": decoded["vsize"], "size": decoded["size"]}


def rejection_matches(consensus, txid, input_index):
    return (consensus.get("accepted") is False and consensus.get("rpc_code") == -25 and
            consensus.get("reason", "").startswith(
                CONSENSUS_REJECTION + str(input_index) + " of " + txid))


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
    if (template["experiment"] != "binohash-single-bug-pinning-skip" or
            template["funding_txid"] != ZERO_TXID or
            template["bug_digest_hex"] != BUG_DIGEST or
            template["anchor_signature_hex"] != "300602010102010103" or
            template["input_value_sat"] != INPUT_VALUE or
            [row["mutation"] for row in template["rows"]] != list(MUTATIONS) or
            set(template["controls"]) != set(CONTROLS)):
        raise RuntimeError("Pinning-skip template changed")
    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    easy = bytes.fromhex(template["easy_script_pubkey_hex"])
    anchor = bytes.fromhex(template["anchor_script_pubkey_hex"])
    outputs = []
    for _ in range(11):
        # One disjoint pair per row/control, plus both possible prevout aliases.
        outputs.extend([(INPUT_VALUE, easy), (INPUT_VALUE, anchor),
                        (INPUT_VALUE, easy), (INPUT_VALUE, anchor)])
    outputs.append((5_000_000_000 - 44 * INPUT_VALUE - FUNDING_FEE,
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
    for key in ("experiment", "input_value_sat", "fee_sat", "anchor_signature_hex",
                "anchor_signature_bytes", "anchor_pubkey_hex",
                "anchor_redeem_script_hex", "anchor_redeem_script_bytes",
                "anchor_script_pubkey_hex", "easy_script_pubkey_hex",
                "destination_script_pubkey_hex", "bug_digest_hex"):
        if funded[key] != template[key]:
            raise RuntimeError(f"Funding changed fixture field: {key}")
    report["fixture"] = {key: funded[key] for key in
                         ("anchor_signature_hex", "anchor_signature_bytes",
                          "anchor_pubkey_hex", "anchor_redeem_script_hex",
                          "anchor_redeem_script_bytes", "anchor_script_pubkey_hex",
                          "easy_script_pubkey_hex", "bug_digest_hex")}
    report["controls"] = {}
    for name, input_index in CONTROLS.items():
        control = funded["controls"][name]
        tx = control["transaction"]
        decoded = decoded_matches(node, tx)
        consensus = consensus_probe(node, address, tx, False)
        if (control["anchor_input_index"] != input_index or
                control["local_digest_hex"] == BUG_DIGEST or
                not rejection_matches(consensus, tx["txid"], input_index)):
            raise RuntimeError(f"Unexpected boundary-control result: {name}")
        report["controls"][name] = {**control, "decoded": decoded,
                                    "consensus": consensus}
    report["rows"] = []
    transactions = []
    for row in funded["rows"]:
        tx = row["transaction"]
        decoded = decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if (row["local_digest_hex"] != BUG_DIGEST or
                tx["output_count"] != 1 or
                policy.get("allowed") is not False or
                policy.get("reject-reason") != POLICY_REJECTION or
                policy.get("txid") != tx["txid"]):
            raise RuntimeError(f"Unexpected policy/digest result: {row['mutation']}: {policy}")
        report["rows"].append({**row, "decoded": decoded, "policy": policy})
        transactions.append(tx["hex"])
    height = node.rpc("getblockcount")
    block_hash = node.rpc("generateblock", address, transactions)["hash"]
    block = node.rpc("getblock", block_hash)
    txids = {row["transaction"]["txid"] for row in report["rows"]}
    if (block["height"] != height + 1 or
            not txids.issubset(set(block["tx"])) or len(txids) != 9):
        raise RuntimeError("Core did not confirm nine bug-boundary variants")
    report["consensus"] = {"accepted": True, "block_hash": block_hash,
                           "block_height": block["height"],
                           "confirmed_txids": len(txids)}


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-single-bug-pinning-skip" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            report.get("fixture", {}).get("anchor_signature_hex") != "300602010102010103" or
            report.get("fixture", {}).get("anchor_signature_bytes") != 9 or
            report.get("fixture", {}).get("anchor_redeem_script_bytes") != 45 or
            report.get("fixture", {}).get("bug_digest_hex") != BUG_DIGEST or
            report.get("consensus", {}).get("accepted") is not True or
            report.get("consensus", {}).get("confirmed_txids") != 9 or
            len(report.get("rows", [])) != 9 or
            set(report.get("controls", {})) != set(CONTROLS)):
        return False
    rows = report["rows"]
    if ([row.get("mutation") for row in rows] != list(MUTATIONS) or
            len({row["transaction"]["txid"] for row in rows}) != 9):
        return False
    for case, row in enumerate(rows):
        tx = row["transaction"]
        if (row.get("local_digest_hex") != BUG_DIGEST or
                tx.get("output_count") != 1 or
                tx.get("input_vouts") !=
                ([4 * case + 2 if case in (4, 8) else 4 * case,
                  4 * case + 3 if case in (2, 8) else 4 * case + 1]) or
                tx.get("script_sig_bytes") != [2, 46] or
                tx.get("txid") != row.get("decoded", {}).get("txid") or
                row.get("policy", {}).get("allowed") is not False or
                row["policy"].get("reject-reason") != POLICY_REJECTION or
                row["policy"].get("txid") != tx.get("txid")):
            return False
    for name, input_index in CONTROLS.items():
        control = report["controls"][name]
        tx = control["transaction"]
        if (control.get("anchor_input_index") != input_index or
                control.get("local_digest_hex") == BUG_DIGEST or
                not rejection_matches(control.get("consensus", {}), tx["txid"], input_index) or
                control.get("decoded", {}).get("txid") != tx["txid"]):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-single-bug-pinning-skip-v30.3.json")
    args = parser.parse_args()
    report = {
        "schema_version": 1,
        "experiment": "funded-binohash-single-bug-pinning-skip",
        "initial_mocktime": START_TIME,
        "scope": "Nine disjoint two-input legacy P2SH spends retain an embedded nine-byte SIGHASH_SINGLE signature while the anchor input index exceeds output count. Two boundary-crossing controls fail. Direct Core block verdicts, but default policy rejects all accepted spends under CONST_SCRIPTCODE. No full Binohash pinning or security bound.",
    }
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-single-skip-") as directory:
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
