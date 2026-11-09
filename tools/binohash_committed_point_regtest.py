#!/usr/bin/env python3
"""Compare a funded committed ECDSA point lock against pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from binohash_core_regtest import consensus_probe
from core_regtest import RELEASE, ROOT, START_TIME, Node, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_committed_point_core"
ZERO_TXID = "00" * 32
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000
CONSENSUS_PREFIX = "TestBlockValidity failed: block-script-verify-flag-failed ("
REJECTIONS = {
    "wrong_signature": "Script failed an OP_EQUALVERIFY operation",
    "added_output": "Script evaluated without error but finished with a false/empty top stack element",
}
POLICY_REJECTIONS = {
    "wrong_signature": "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
    "added_output": "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)",
}


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


def rejection_matches(consensus, name, txid):
    return (consensus.get("accepted") is False and consensus.get("rpc_code") == -25 and
            consensus.get("reason", "").startswith(
                CONSENSUS_PREFIX + REJECTIONS[name] + "), input 1 of " + txid))


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
    if (base["experiment"] != "binohash-committed-point-core" or
            base["funding_txid"] != ZERO_TXID or
            base["input_value_sat"] != INPUT_VALUE or
            base["expected_point_secret_hex"] != base["extracted_point_secret_hex"] or
            base["redeem_script_bytes"] > 520):
        raise RuntimeError("Committed point-lock manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    outputs = [(INPUT_VALUE, bytes.fromhex(base["easy_script_pubkey_hex"])),
               (INPUT_VALUE, bytes.fromhex(base["point_script_pubkey_hex"])),
               (5_000_000_000 - 2 * INPUT_VALUE - FUNDING_FEE,
                bytes.fromhex(destination))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination)
    static_keys = ("experiment", "input_value_sat", "fee_sat", "signing_pubkey_hex",
                   "public_signing_scalar_hex", "target_point_hex",
                   "expected_point_secret_hex", "extracted_point_secret_hex",
                   "signature_hex", "signature_bytes", "substitute_signature_hex", "signature_commitment_hex",
                   "bug_digest_hex", "redeem_script_hex", "redeem_script_bytes",
                   "point_script_pubkey_hex", "point_script_pubkey_bytes", "easy_script_pubkey_hex",
                   "hint_items", "witness_items",
                   "destination_script_pubkey_hex")
    if any(funded[key] != base[key] for key in static_keys):
        raise RuntimeError("Funding changed committed point-lock fixture")
    report["fixture"] = {key: funded[key] for key in static_keys}
    report["controls"] = {}
    for name in REJECTIONS:
        tx = funded["transactions"][name]
        decoded = decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        consensus = consensus_probe(node, address, tx, False)
        if (not rejection_matches(consensus, name, tx["txid"]) or
                policy.get("allowed") is not False or
                policy.get("reject-reason") != POLICY_REJECTIONS[name]):
            raise RuntimeError(f"Unexpected consensus rejection for {name}")
        report["controls"][name] = {"transaction": tx, "decoded": decoded,
                                    "policy": policy, "consensus": consensus}
    tx = funded["transactions"]["valid"]
    decoded = decoded_matches(node, tx)
    policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
    if policy.get("allowed") is not True:
        raise RuntimeError("Valid point lock was not accepted by default policy")
    consensus = consensus_probe(node, address, tx, True)
    report["valid"] = {"transaction": tx, "decoded": decoded,
                       "policy": policy, "consensus": consensus}


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-committed-point-lock" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            set(report.get("controls", {})) != set(REJECTIONS)):
        return False
    fixture = report["fixture"]
    if (fixture["expected_point_secret_hex"] != fixture["extracted_point_secret_hex"] or
            fixture["signature_hex"] == fixture["substitute_signature_hex"] or
            fixture["bug_digest_hex"] != "01" + "00" * 31 or
            fixture["signature_bytes"] != len(fixture["signature_hex"]) // 2 or
            fixture["redeem_script_bytes"] != len(fixture["redeem_script_hex"]) // 2 or
            fixture["redeem_script_bytes"] > 520 or
            fixture["point_script_pubkey_bytes"] != 23 or
            len(fixture["point_script_pubkey_hex"]) != 46 or
            fixture["hint_items"] != 0 or fixture["witness_items"] != 0):
        return False
    valid = report["valid"]
    if (valid["consensus"].get("accepted") is not True or
            valid["policy"].get("allowed") is not True or
            valid["transaction"]["txid"] != valid["decoded"]["txid"] or
            valid["transaction"]["txid"] != valid["policy"].get("txid") or
            valid["transaction"]["input_vouts"] != [0, 1] or
            valid["transaction"]["output_count"] != 1 or
            valid["transaction"]["weight"] != 1124 or
            valid["transaction"]["input_script_sig_bytes"] != [2, 144]):
        return False
    for name, count in (("wrong_signature", 1), ("added_output", 2)):
        control = report["controls"][name]
        tx = control["transaction"]
        if (not rejection_matches(control["consensus"], name, tx["txid"]) or
                control["policy"].get("allowed") is not False or
                control["policy"].get("reject-reason") != POLICY_REJECTIONS[name] or
                tx["txid"] != control["decoded"]["txid"] or
                tx["txid"] == valid["transaction"]["txid"] or
                tx["input_vouts"] != [0, 1] or tx["output_count"] != count):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-committed-point-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-committed-point-lock",
              "initial_mocktime": START_TIME,
              "scope": "Funded legacy P2SH committed ECDSA point lock with substitution and added-output controls. No full Binohash protocol or off-chain setup-proof claim."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-point-") as directory:
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
