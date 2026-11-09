#!/usr/bin/env python3
"""Funded G/2 small-R P2SH point lock against pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import RELEASE, ROOT, START_TIME, Node, RPCError, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "pointlock_small_r_core_fixtures"
ZERO_TXID = "00" * 32
FUNDING_VALUE = 1_000_000
FUNDING_FEE = 10_000
VERIFY_ERROR = "Script failed an OP_VERIFY operation"


def generate(funding_txid, destination_script):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx, fixture, name):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if tx["base_bytes"] != tx["total_bytes"] or tx["weight"] != 4 * tx["base_bytes"]:
        raise RuntimeError("Expected a complete legacy transaction without witness")
    for expected, actual in (("txid", "txid"), ("weight", "weight"),
                             ("vsize", "vsize"), ("total_bytes", "size")):
        if tx[expected] != decoded[actual]:
            raise RuntimeError(f"Core and Rust disagree on {expected}")
    if decoded["hash"] != tx["txid"] or len(decoded["vin"]) != 1 or len(decoded["vout"]) != 1:
        raise RuntimeError("Decoded legacy transaction shape changed")
    script_sig = decoded["vin"][0]["scriptSig"]["hex"]
    signature = bytes.fromhex(fixture[f"{name}_signature_hex"])
    redeem = bytes.fromhex(fixture["redeem_script_hex"])
    expected_script_sig = (bytes([len(signature)]) + signature +
                           bytes([len(redeem)]) + redeem).hex()
    if script_sig != expected_script_sig or len(script_sig) // 2 != tx["script_sig_bytes"]:
        raise RuntimeError("Core decoded a different published signature or redeemScript")
    return {"txid": decoded["txid"], "weight": decoded["weight"],
            "vsize": decoded["vsize"], "size": decoded["size"],
            "script_sig_hex": script_sig}


def consensus_probe(node, address, tx, expected_accept):
    height = node.rpc("getblockcount")
    try:
        result = node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        if expected_accept or error.code != -25 or VERIFY_ERROR not in error.message:
            raise RuntimeError(f"Unexpected Core block verdict: {error.message}") from error
        if node.rpc("getblockcount") != height:
            raise RuntimeError("Rejected control changed chain height")
        return {"accepted": False, "rpc_code": error.code, "reason": error.message}
    if not expected_accept:
        raise RuntimeError("Overlength signature entered a block")
    block = node.rpc("getblock", result["hash"])
    if block["height"] != height + 1 or tx["txid"] not in block["tx"]:
        raise RuntimeError("Accepted block omitted the point-lock spend")
    return {"accepted": True, "block_hash": result["hash"], "block_height": block["height"]}


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
    manifest = generate(ZERO_TXID, destination_script)
    if (manifest["experiment"] != "pointlock-g-half-funded-p2sh-core" or
            manifest["funding_txid"] != ZERO_TXID or
            manifest["input_value_sat"] != FUNDING_VALUE or
            manifest["redeem_script_bytes"] != 40 or
            manifest["extracted_secret_matches"] is not True or
            manifest["honest_signature_bytes"] > 60 or
            manifest["ordinary_signature_bytes"] <= 60):
        raise RuntimeError("Small-R fixture manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination_script)
    outputs = [(FUNDING_VALUE, bytes.fromhex(manifest["p2sh_script_pubkey_hex"])),
               (5_000_000_000 - FUNDING_VALUE - FUNDING_FEE,
                bytes.fromhex(destination_script))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination_script)
    for key in ("experiment", "input_value_sat", "fee_sat", "point_secret_hex",
                "point_compressed_hex", "redeem_script_hex", "redeem_script_bytes",
                "p2sh_script_pubkey_hex", "destination_script_pubkey_hex"):
        if funded[key] != manifest[key]:
            raise RuntimeError(f"Funding changed embedded fixture: {key}")
    if funded["funding_txid"] != funding["txid"] or funded["extracted_secret_matches"] is not True:
        raise RuntimeError("Funded fixture failed extraction")
    report["fixture"] = funded

    control = funded["length_control"]
    honest = funded["honest"]
    if control["txid"] == honest["txid"]:
        raise RuntimeError("Length mutation did not change transaction identity")
    control_decoded = decoded_matches(node, control, funded, "ordinary")
    honest_decoded = decoded_matches(node, honest, funded, "honest")
    control_policy = node.rpc("testmempoolaccept", [control["hex"]])[0]
    control_consensus = consensus_probe(node, address, control, False)
    honest_policy = node.rpc("testmempoolaccept", [honest["hex"]])[0]
    honest_consensus = consensus_probe(node, address, honest, True)
    report["results"] = {
        "length_control": {"transaction": control, "decoded": control_decoded,
                           "policy": control_policy, "consensus": control_consensus},
        "honest": {"transaction": honest, "decoded": honest_decoded,
                   "policy": honest_policy, "consensus": honest_consensus},
    }


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-pointlock-g-half-p2sh" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"]):
        return False
    fixture = report.get("fixture", {})
    rows = report.get("results", {})
    if (fixture.get("extracted_secret_matches") is not True or
            fixture.get("experiment") != "pointlock-g-half-funded-p2sh-core" or
            fixture.get("redeem_script_bytes") != 40 or
            fixture.get("funding_txid") != report.get("funding_transaction", {}).get("txid") or
            fixture.get("honest_signature_bytes", 1000) > 60 or
            fixture.get("ordinary_signature_bytes", 0) <= 60 or
            set(rows) != {"honest", "length_control"}):
        return False
    honest, control = rows["honest"], rows["length_control"]
    for name, row in (("honest", honest), ("ordinary", control)):
        tx = row["transaction"]
        signature = bytes.fromhex(fixture[f"{name}_signature_hex"])
        redeem = bytes.fromhex(fixture["redeem_script_hex"])
        expected_script_sig = (bytes([len(signature)]) + signature +
                               bytes([len(redeem)]) + redeem).hex()
        if (len(signature) != fixture[f"{name}_signature_bytes"] or
                tx["base_bytes"] != tx["total_bytes"] or
                tx["weight"] != 4 * tx["base_bytes"] or
                tx["script_sig_bytes"] != len(expected_script_sig) // 2 or
                row["decoded"]["script_sig_hex"] != expected_script_sig or
                row["decoded"]["weight"] != tx["weight"] or
                row["decoded"]["size"] != tx["total_bytes"] or
                row["policy"].get("txid") != tx["txid"]):
            return False
    return (honest["consensus"].get("accepted") is True and
            honest["policy"].get("allowed") is True and
            control["consensus"].get("accepted") is False and
            control["consensus"].get("rpc_code") == -25 and
            VERIFY_ERROR in control["consensus"].get("reason", "") and
            control["policy"].get("allowed") is False and
            VERIFY_ERROR in control["policy"].get("reject-reason", "") and
            honest["decoded"]["txid"] == honest["transaction"]["txid"] and
            control["decoded"]["txid"] == control["transaction"]["txid"] and
            honest["transaction"]["txid"] != control["transaction"]["txid"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/pointlock-small-r-core-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-pointlock-g-half-p2sh",
              "initial_mocktime": START_TIME, "results": {},
              "scope": "One funded P2SH G/2 small-R spend and one ordinary valid ECDSA signature rejected by the 60-byte guard. Extraction uses the local algebraic helper and the exact signature Core decodes. No generic forgery bound or full Binohash protocol is claimed."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-small-r-") as directory:
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
