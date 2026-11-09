#!/usr/bin/env python3
"""Compare all raw legacy ECDSA sighash bytes with pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (RELEASE, ROOT, START_TIME, Node, RPCError, core_binary,
                          transaction)
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_sighash_flag_fixtures"
ZERO_TXID = "00" * 32
INPUT_VALUE = 100_000
FUNDING_FEE = 50_000
CANONICAL = {1, 2, 3, 129, 130, 131}
POLICY_REJECTION = "mempool-script-verify-flag-failed (Signature hash type missing or not understood)"
CONSENSUS_REJECTION = ("TestBlockValidity failed: block-script-verify-flag-failed "
                       "(Script evaluated without error but finished with a false/empty top "
                       "stack element), input 0 of ")


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
            tx["vsize"] != decoded["vsize"] or
            tx["total_bytes"] != decoded["size"] or
            len(decoded["vin"]) != 1 or len(decoded["vout"]) != 1 or
            len(decoded["vin"][0]["scriptSig"]["hex"]) // 2 != tx["script_sig_bytes"] or
            "txinwitness" in decoded["vin"][0]):
        raise RuntimeError("Rust and Core disagree on legacy transaction serialization")


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
    if (base["experiment"] != "binohash-raw-sighash-byte-census" or
            base["funding_txid"] != ZERO_TXID or
            base["input_value_sat"] != INPUT_VALUE or
            len(base["results"]) != 256):
        raise RuntimeError("Sighash flag manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination_script)
    lock = bytes.fromhex(base["p2sh_script_pubkey_hex"])
    outputs = [(INPUT_VALUE, lock)] * 256 + [
        (5_000_000_000 - 256 * INPUT_VALUE - FUNDING_FEE,
         bytes.fromhex(destination_script))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination_script)
    for key in ("experiment", "input_value_sat", "fee_sat", "redeem_script_hex",
                "redeem_script_bytes", "p2sh_script_pubkey_hex",
                "destination_script_pubkey_hex"):
        if funded[key] != base[key]:
            raise RuntimeError(f"Funding changed static fixture field: {key}")
    if (funded["funding_txid"] != funding["txid"] or
            [row["flag"] for row in funded["results"]] != list(range(256))):
        raise RuntimeError("Funded flag census shape changed")
    report["fixture"] = {key: funded[key] for key in
                         ("input_value_sat", "fee_sat", "redeem_script_hex",
                          "redeem_script_bytes", "p2sh_script_pubkey_hex")}
    fixed_digests = funded["fixed_template_digests_hex"]
    if len(fixed_digests) != 256 or len(set(fixed_digests)) != 256:
        raise RuntimeError("Raw flag bytes did not yield 256 fixed-template digests")
    report["fixed_template_digests_hex"] = fixed_digests

    wrong = funded["wrong_flag_transaction"]
    decoded_matches(node, wrong)
    try:
        node.rpc("generateblock", address, [wrong["hex"]])
    except RPCError as error:
        if error.code != -25 or not error.message.startswith(CONSENSUS_REJECTION + wrong["txid"]):
            raise RuntimeError(f"Unexpected wrong-flag consensus rejection: {error.message}")
        report["wrong_flag_control"] = {"txid": wrong["txid"], "rpc_code": error.code,
                                        "reason": error.message, "accepted": False}
    else:
        raise RuntimeError("Wrong-flag control entered a block")

    report["rows"] = []
    transactions = []
    for row in funded["results"]:
        tx = row["transaction"]
        decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        flag = row["flag"]
        if (row["canonical"] != (flag in CANONICAL) or
                policy.get("allowed") is not (flag in CANONICAL) or
                (flag not in CANONICAL and
                 policy.get("reject-reason") != POLICY_REJECTION) or
                policy.get("txid") != tx["txid"]):
            raise RuntimeError(f"Unexpected policy outcome for raw flag {flag:#04x}: {policy}")
        report["rows"].append({
            "flag": flag, "canonical": row["canonical"],
            "local_digest_hex": row["local_digest_hex"],
            "signature_bytes": row["signature_bytes"],
            "txid": tx["txid"], "weight": tx["weight"],
            "script_sig_bytes": tx["script_sig_bytes"],
            "policy_allowed": policy["allowed"],
            "policy_reject_reason": policy.get("reject-reason"),
        })
        transactions.append(tx["hex"])
    report["sample_transaction"] = funded["results"][1]["transaction"]
    height = node.rpc("getblockcount")
    block = node.rpc("generateblock", address, transactions)["hash"]
    confirmed = node.rpc("getblock", block)
    txids = {row["txid"] for row in report["rows"]}
    if (confirmed["height"] != height + 1 or
            not txids.issubset(set(confirmed["tx"])) or
            len(txids) != 256):
        raise RuntimeError("Core block did not confirm all 256 raw-flag spends")
    report["consensus"] = {"accepted": True, "block_hash": block,
                           "block_height": confirmed["height"],
                           "confirmed_txids": len(txids)}


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-raw-sighash-byte-census" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            report.get("fixture", {}).get("redeem_script_bytes") != 35 or
            report.get("consensus", {}).get("accepted") is not True or
            report.get("consensus", {}).get("confirmed_txids") != 256 or
            len(report.get("fixed_template_digests_hex", [])) != 256 or
            len(set(report["fixed_template_digests_hex"])) != 256 or
            len(report.get("rows", [])) != 256):
        return False
    rows = report["rows"]
    if ([row["flag"] for row in rows] != list(range(256)) or
            len({row["local_digest_hex"] for row in rows}) != 256 or
            len({row["txid"] for row in rows}) != 256 or
            {row["flag"] for row in rows if row["policy_allowed"]} != CANONICAL):
        return False
    for row in rows:
        if (row["canonical"] != (row["flag"] in CANONICAL) or
                (row["flag"] not in CANONICAL and
                 row["policy_reject_reason"] != POLICY_REJECTION)):
            return False
    control = report.get("wrong_flag_control", {})
    return (control.get("accepted") is False and control.get("rpc_code") == -25 and
            control.get("reason", "").startswith(CONSENSUS_REJECTION +
                                                    control.get("txid", "")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-sighash-flags-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-raw-sighash-byte-census",
              "initial_mocktime": START_TIME,
              "scope": "256 disjoint signed P2SH spends classify raw legacy sighash bytes under pinned Core consensus and default policy. No FindAndDelete subset grind, transaction pinning or security bound."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-flags-") as directory:
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
