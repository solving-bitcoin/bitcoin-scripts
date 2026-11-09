#!/usr/bin/env python3
"""Compare an embedded nine-byte SIGHASH_SINGLE bug anchor with pinned Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from binohash_core_regtest import POLICY_REJECTION, consensus_probe
from core_regtest import RELEASE, ROOT, START_TIME, Node, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_single_bug_anchor"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000
CONTROLS = ("added_output", "moved_input")
CONSENSUS_REJECTION = ("TestBlockValidity failed: block-script-verify-flag-failed "
                       "(Script evaluated without error but finished with a false/empty top "
                       "stack element), input ")


def generate(funding_txid, destination_script):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if (tx["base_bytes"] != tx["total_bytes"] or
            tx["weight"] != 4 * tx["base_bytes"] or
            decoded["txid"] != tx["txid"] or decoded["weight"] != tx["weight"] or
            decoded["vsize"] != tx["vsize"] or decoded["size"] != tx["total_bytes"] or
            len(decoded["vin"]) != 2 or len(decoded["vout"]) != tx["output_count"] or
            [item["vout"] for item in decoded["vin"]] != tx["input_vouts"] or
            any("txinwitness" in item for item in decoded["vin"])):
        raise RuntimeError("Core and Rust disagree on legacy transaction shape")
    for index, item in enumerate(decoded["vin"]):
        if len(item["scriptSig"]["hex"]) // 2 != tx["input_script_sig_bytes"][index]:
            raise RuntimeError("Core and Rust disagree on scriptSig length")
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
    base = generate(ZERO_TXID, destination)
    if (base["experiment"] != "binohash-nine-byte-single-anchor" or
            base["funding_txid"] != ZERO_TXID or
            base["anchor_signature_bytes"] != 9 or
            base["input_value_sat"] != INPUT_VALUE or
            base["anchor_redeem_script_bytes"] > 520):
        raise RuntimeError("Nine-byte anchor manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    outputs = [(INPUT_VALUE, bytes.fromhex(base["easy_script_pubkey_hex"])),
               (INPUT_VALUE, bytes.fromhex(base["anchor_script_pubkey_hex"])),
               (5_000_000_000 - 2 * INPUT_VALUE - FUNDING_FEE,
                bytes.fromhex(destination))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination)
    for key in ("experiment", "input_value_sat", "fee_sat", "anchor_signature_hex",
                "anchor_signature_bytes", "anchor_pubkey_hex", "anchor_redeem_script_hex",
                "anchor_redeem_script_bytes", "anchor_script_pubkey_hex",
                "easy_script_pubkey_hex", "destination_script_pubkey_hex"):
        if funded[key] != base[key]:
            raise RuntimeError(f"Funding changed anchor fixture: {key}")
    report["fixture"] = {key: funded[key] for key in
                         ("anchor_signature_hex", "anchor_signature_bytes", "anchor_pubkey_hex",
                          "anchor_redeem_script_hex", "anchor_redeem_script_bytes",
                          "anchor_script_pubkey_hex", "local_digests")}
    report["controls"] = {}
    for name, input_index in (("added_output", 1), ("moved_input", 0)):
        tx = funded["transactions"][name]
        decoded = decoded_matches(node, tx)
        consensus = consensus_probe(node, address, tx, False)
        if not rejection_matches(consensus, tx["txid"], input_index):
            raise RuntimeError(f"Unexpected Core rejection for {name}")
        report["controls"][name] = {"transaction": tx, "decoded": decoded,
                                    "consensus": consensus}
    tx = funded["transactions"]["valid"]
    decoded = decoded_matches(node, tx)
    policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
    if (policy.get("allowed") is not False or
            policy.get("reject-reason") != POLICY_REJECTION):
        raise RuntimeError("Unexpected default policy result for anchor")
    consensus = consensus_probe(node, address, tx, True)
    report["valid"] = {"transaction": tx, "decoded": decoded,
                       "policy": policy, "consensus": consensus}


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-nine-byte-anchor" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            report.get("fixture", {}).get("anchor_signature_bytes") != 9 or
            set(report.get("controls", {})) != set(CONTROLS)):
        return False
    fixture = report["fixture"]
    if (fixture["anchor_signature_hex"] != "300602010102010103" or
            fixture["anchor_redeem_script_bytes"] !=
            len(fixture["anchor_redeem_script_hex"]) // 2 or
            fixture["anchor_redeem_script_bytes"] != 45 or
            len(fixture["anchor_script_pubkey_hex"]) != 46 or
            len(fixture["anchor_pubkey_hex"]) != 66 or
            fixture["local_digests"]["valid_hex"] != "01" + "00" * 31 or
            fixture["local_digests"]["added_output_hex"] ==
            fixture["local_digests"]["valid_hex"] or
            fixture["local_digests"]["moved_input_hex"] ==
            fixture["local_digests"]["valid_hex"]):
        return False
    valid = report["valid"]
    if (valid["consensus"].get("accepted") is not True or
            valid["policy"].get("allowed") is not False or
            valid["policy"].get("reject-reason") != POLICY_REJECTION or
            valid["transaction"]["txid"] != valid["decoded"]["txid"] or
            valid["transaction"]["txid"] != valid["policy"].get("txid") or
            valid["transaction"]["input_vouts"] != [0, 1] or
            valid["transaction"]["output_count"] != 1 or
            valid["transaction"]["input_script_sig_bytes"] != [2, 46] or
            valid["transaction"]["weight"] != 732):
        return False
    for name, input_index, vouts, output_count in (
            ("added_output", 1, [0, 1], 2), ("moved_input", 0, [1, 0], 1)):
        control = report["controls"][name]
        tx = control["transaction"]
        if (not rejection_matches(control["consensus"], tx["txid"], input_index) or
                tx["txid"] != control["decoded"]["txid"] or
                tx["txid"] == valid["transaction"]["txid"] or
                tx["input_vouts"] != vouts or tx["output_count"] != output_count):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-single-anchor-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-nine-byte-anchor",
              "initial_mocktime": START_TIME,
              "scope": "One embedded nine-byte SIGHASH_SINGLE signature and two boundary-crossing controls in complete funded legacy P2SH spends. No Binohash pinning or collision-security claim."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-anchor-") as directory:
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
