#!/usr/bin/env python3
"""Funded four-mode bare-legacy pinning probe against pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import RELEASE, ROOT, START_TIME, Node, RPCError, core_binary, transaction
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_four_mode_pinning"
ZERO_TXID = "00" * 32
EASY_OUTPUTS = 64
INPUT_VALUE = 1_000_000
FUNDING_FEE = 10_000


def generate(funding_txid, destination_script):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if (decoded["txid"] != tx["txid"] or decoded["hash"] != tx["txid"] or
            decoded["weight"] != tx["weight"] or decoded["vsize"] != tx["vsize"] or
            decoded["size"] != tx["total_bytes"] or
            tx["base_bytes"] != tx["total_bytes"] or
            tx["weight"] != 4 * tx["base_bytes"] or
            len(decoded["vin"]) != 2 or len(decoded["vout"]) != 2 or
            any("txinwitness" in item for item in decoded["vin"])):
        raise RuntimeError("Core decode disagrees with complete legacy spend")
    if [len(bytes.fromhex(item["scriptSig"]["hex"])) for item in decoded["vin"]] != tx["input_script_sig_bytes"]:
        raise RuntimeError("Core decode disagrees on scriptSig sizes")
    return {"txid": decoded["txid"], "weight": decoded["weight"],
            "vsize": decoded["vsize"], "size": decoded["size"]}


def probe(node, address, tx, accepted):
    height = node.rpc("getblockcount")
    try:
        result = node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        if accepted or node.rpc("getblockcount") != height:
            raise RuntimeError(f"Unexpected block rejection: {error.message}") from error
        return {"accepted": False, "rpc_code": error.code, "reason": error.message}
    if not accepted:
        raise RuntimeError("Mutated pinning transaction entered a block")
    block = node.rpc("getblock", result["hash"])
    if block["height"] != height + 1 or tx["txid"] not in block["tx"]:
        raise RuntimeError("Accepted transaction missing from connected block")
    return {"accepted": True, "block_height": block["height"], "block_hash": result["hash"]}


def run(node, report):
    csv_manifest, _ = csv_generate()
    if (csv_manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
            csv_manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]):
        raise RuntimeError("Pinned address source changed Core version")
    address = csv_manifest["mining_address"]
    destination = node.rpc("validateaddress", address)["scriptPubKey"]
    if destination != csv_manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and mining-address generator disagree")
    report["mining_address"] = address
    report["destination_script_pubkey_hex"] = destination
    template = generate(ZERO_TXID, destination)
    if (template["experiment"] != "binohash-four-mode-pinning" or
            template["flags_hex"] != ["82", "02", "81", "01"] or
            template["target_signature_bytes"] != 71 or
            len(template["mutations"]) != 6 or len(template["wrong_sizes"]) != 4):
        raise RuntimeError("Four-mode fixture template changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination)
    easy = bytes.fromhex(template["easy_script_pubkey_hex"])
    locking = bytes.fromhex(template["locking_script_hex"])
    outputs = [(INPUT_VALUE, easy) for _ in range(EASY_OUTPUTS)]
    outputs.append((INPUT_VALUE, locking))
    outputs.append((5_000_000_000 - (EASY_OUTPUTS + 1) * INPUT_VALUE - FUNDING_FEE,
                    bytes.fromhex(destination)))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    funding_decoded = node.rpc("decoderawtransaction", funding["hex"])
    if any(funding_decoded[actual] != funding[expected] for expected, actual in
           (("txid", "txid"), ("weight", "weight"), ("vsize", "vsize"),
            ("total_bytes", "size"))):
        raise RuntimeError("Core decode disagrees with funding transaction")
    funded_block = node.rpc("generateblock", address, [funding["hex"]])
    if funding["txid"] not in node.rpc("getblock", funded_block["hash"])["tx"]:
        raise RuntimeError("Nonstandard bare output was not funded in a block")
    report["funding_transaction"] = funding
    report["funding_decoded"] = {
        "txid": funding_decoded["txid"], "weight": funding_decoded["weight"],
        "vsize": funding_decoded["vsize"], "size": funding_decoded["size"]}
    report["funding_block_hash"] = funded_block["hash"]
    fixture = generate(funding["txid"], destination)
    for key in ("locking_script_hex", "locking_script_bytes", "easy_script_pubkey_hex",
                "flags_hex", "target_signature_bytes", "input_value_sat", "fee_sat"):
        if fixture[key] != template[key]:
            raise RuntimeError(f"Funding altered fixture construction: {key}")
    report["fixture"] = fixture
    report["valid_decoded"] = decoded_matches(node, fixture["valid"])
    report["valid_policy"] = node.rpc("testmempoolaccept", [fixture["valid"]["hex"]])[0]
    if (report["valid_policy"].get("allowed") is not False or
            report["valid_policy"].get("reject-reason") != "bad-txns-nonstandard-inputs"):
        raise RuntimeError("Expected default-policy rejection of bare legacy input")
    report["mutations"] = []
    for mutation in fixture["mutations"]:
        tx = mutation["transaction"]
        decoded = decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        consensus = probe(node, address, tx, False)
        if (policy.get("allowed") is not False or consensus.get("rpc_code") != -25 or
                "block-script-verify-flag-failed" not in consensus.get("reason", "") or
                "input 1 of " not in consensus.get("reason", "")):
            raise RuntimeError(f"Unexpected mutated-spend category: {mutation['name']}")
        report["mutations"].append({"name": mutation["name"],
                                    "changed_modes": mutation["changed_modes"],
                                    "decoded": decoded, "policy": policy,
                                    "consensus": consensus})
    report["wrong_sizes"] = []
    for row in fixture["wrong_sizes"]:
        tx = row["transaction"]
        decoded = decoded_matches(node, tx)
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        consensus = probe(node, address, tx, False)
        if (policy.get("allowed") is not False or consensus.get("rpc_code") != -25 or
                "Script failed an OP_EQUALVERIFY operation" not in consensus.get("reason", "") or
                "input 1 of " not in consensus.get("reason", "")):
            raise RuntimeError(f"Unexpected size-control result at phase {row['phase']}")
        report["wrong_sizes"].append({"phase": row["phase"], "decoded": decoded,
                                      "policy": policy, "consensus": consensus})
    report["valid_consensus"] = probe(node, address, fixture["valid"], True)


def report_passed(report):
    """Check that a stored report still establishes the claimed Core boundary."""
    try:
        if ("infrastructure_error" in report or report["schema_version"] != 1 or
                report["experiment"] != "funded-binohash-four-mode-pinning" or
                report["bitcoin_core"]["commit"] != RELEASE["commit"] or
                report["initial_mocktime"] != START_TIME):
            return False
        fixture = report["fixture"]
        valid = fixture["valid"]
        funding = report["funding_transaction"]
        if (fixture["experiment"] != "binohash-four-mode-pinning" or
                fixture["funding_txid"] != funding["txid"] or
                fixture["flags_hex"] != ["82", "02", "81", "01"] or
                fixture["target_signature_bytes"] != 71 or
                fixture["attempts"] != [6, 3, 2, 1] or
                fixture["hint_items"] != 0 or fixture["witness_items"] != 0 or
                fixture["locking_script_bytes"] != 159 or
                len(bytes.fromhex(fixture["locking_script_hex"])) != 159 or
                fixture["static_non_push_opcodes"] != 15 or
                [len(bytes.fromhex(s)) for s in fixture["script_codes_hex"]] != [156, 117, 78, 39] or
                [len(bytes.fromhex(s)) for s in fixture["signatures_hex"]] != [71] * 4 or
                [s[-2:] for s in fixture["signatures_hex"]] != fixture["flags_hex"] or
                len(fixture["digests_hex"]) != 4):
            return False
        def consistent(tx, decoded):
            return (len(bytes.fromhex(tx["hex"])) == tx["total_bytes"] and
                    decoded["txid"] == tx["txid"] and decoded["weight"] == tx["weight"] and
                    decoded["vsize"] == tx["vsize"] and decoded["size"] == tx["total_bytes"])
        if (not consistent(funding, report["funding_decoded"]) or
                [funding[k] for k in ("base_bytes", "total_bytes", "weight", "vsize")] !=
                [2310, 2315, 9245, 2312] or
                not consistent(valid, report["valid_decoded"]) or
                [valid[k] for k in ("base_bytes", "total_bytes", "weight", "vsize")] !=
                [439, 439, 1756, 439] or
                valid["input_script_sig_bytes"] != [2, 288] or
                report["valid_policy"]["allowed"] is not False or
                report["valid_policy"]["reject-reason"] != "bad-txns-nonstandard-inputs" or
                report["valid_consensus"]["accepted"] is not True or
                report["valid_consensus"]["block_height"] != 103):
            return False
        expected_fields = [
            ("version", [True] * 4),
            ("selected_sequence", [True] * 4),
            ("locktime", [True] * 4),
            ("other_prevout", [False, True, False, True]),
            ("output_data", [False, False, True, True]),
            ("other_sequence", [False, False, False, True]),
        ]
        if len(report["mutations"]) != 6 or len(fixture["mutations"]) != 6:
            return False
        for index, (name, pattern) in enumerate(expected_fields):
            row = report["mutations"][index]
            raw = fixture["mutations"][index]
            tx = raw["transaction"]
            reason = ("Script evaluated without error but finished with a false/empty top stack element"
                      if name == "other_sequence" else "Script failed an OP_CHECKSIGVERIFY operation")
            prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                      f"({reason}), input 1 of {tx['txid']}")
            if (row["name"] != name or raw["name"] != name or
                    row["changed_modes"] != pattern or raw["changed_modes"] != pattern or
                    len(raw["digests_hex"]) != 4 or
                    [raw["digests_hex"][i] != fixture["digests_hex"][i] for i in range(4)] != pattern or
                    not consistent(tx, row["decoded"]) or
                    row["policy"]["allowed"] is not False or
                    row["policy"]["reject-reason"] != "bad-txns-nonstandard-inputs" or
                    row["consensus"]["accepted"] is not False or
                    row["consensus"]["rpc_code"] != -25 or
                    not row["consensus"]["reason"].startswith(prefix)):
                return False
        if len(report["wrong_sizes"]) != 4 or len(fixture["wrong_sizes"]) != 4:
            return False
        for phase, (row, raw) in enumerate(zip(report["wrong_sizes"], fixture["wrong_sizes"])):
            tx = raw["transaction"]
            prefix = ("TestBlockValidity failed: block-script-verify-flag-failed "
                      "(Script failed an OP_EQUALVERIFY operation), input 1 of " + tx["txid"])
            if (row["phase"] != phase or raw["phase"] != phase or
                    not consistent(tx, row["decoded"]) or
                    tx["input_script_sig_bytes"] != [2, 287] or
                    row["policy"]["allowed"] is not False or
                    row["policy"]["reject-reason"] != "bad-txns-nonstandard-inputs" or
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
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-four-mode-pinning-v30.3.json")
    args = parser.parse_args()
    report = {
        "schema_version": 1,
        "experiment": "funded-binohash-four-mode-pinning",
        "initial_mocktime": START_TIME,
        "scope": "Reduced four-mode bare-legacy signature-size pinning with deterministic public keys and cheap 71-byte predicates; no full Binohash security or grinding claim.",
    }
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-four-mode-") as directory:
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
