#!/usr/bin/env python3
"""Compare BIP68 height/time boundaries with pinned Core on funded CSV spends."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                          RPCError, core_binary, interpreter_provenance, transaction)
from tapscript_csv_regtest import (csv_transaction, generate, validate_funded_manifest,
                                   validate_witness)

NAMES = ("csv-high-height-exact", "csv-high-time-exact")
CSV_UNITS = 5
SECONDS_PER_UNIT = 512
BLOCK_REJECTION = "TestBlockValidity failed: bad-txns-nonfinal, contains a non-BIP68-final transaction "
POLICY_REJECTION = "non-BIP68-final"


def tick_512(node):
    """Give mined blocks an exact 512-second cadence without changing other harnesses."""
    node.mocktime += SECONDS_PER_UNIT
    node.rpc("setmocktime", node.mocktime)


def maturity_rejection_matches(result, txid, policy=False):
    if policy:
        return (result.get("allowed") is False and result.get("txid") == txid and
                result.get("reject-reason") == POLICY_REJECTION)
    return (result.get("accepted") is False and result.get("rpc_code") == -25 and
            result.get("reason") == BLOCK_REJECTION + txid)


def rejected_consensus_probe(node, address, tx):
    height = node.rpc("getblockcount")
    try:
        node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        result = {"accepted": False, "rpc_code": error.code, "reason": error.message}
        if not maturity_rejection_matches(result, tx["txid"]):
            raise RuntimeError(f"Unexpected immature-block rejection: {result}") from error
        if node.rpc("getblockcount") != height:
            raise RuntimeError("Rejected maturity probe changed chain height")
        return result
    raise RuntimeError("Immature BIP68 spend entered a block")


def local_probe(tx, funding_height, funding_parent_mtp, candidate_height, candidate_parent_mtp):
    request = {"tx_hex": tx["hex"], "funding_height": funding_height,
               "funding_parent_mtp": funding_parent_mtp,
               "candidate_height": candidate_height,
               "candidate_parent_mtp": candidate_parent_mtp}
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", "bip68_maturity_probe"],
        input=json.dumps(request).encode(), cwd=ROOT)
    result = json.loads(raw)
    if result.get("txid") != tx["txid"]:
        raise RuntimeError("Local sequence-lock probe used a different transaction")
    return result


def snapshot(node, funding_height, funding_parent_mtp):
    tip_hash = node.rpc("getbestblockhash")
    tip = node.rpc("getblockheader", tip_hash)
    return {"tip_hash": tip_hash, "tip_height": tip["height"],
            "tip_time": tip["time"],
            "candidate_height": tip["height"] + 1,
            "candidate_parent_mtp": tip["mediantime"],
            "height_since_funding": tip["height"] + 1 - funding_height,
            "mtp_since_funding_parent": tip["mediantime"] - funding_parent_mtp}


def selected_transactions(funded, funding_txid, mining_script):
    rows = {}
    for name in NAMES:
        fixture = next((row for row in funded["fixtures"] if row["name"] == name), None)
        if fixture is None:
            raise RuntimeError(f"Missing fixture {name}")
        witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
        witness.extend([bytes.fromhex(fixture["script_hex"]),
                        bytes.fromhex(fixture["control_block_hex"])])
        tx = csv_transaction(funding_txid, fixture["funding_vout"], witness,
                             [(FUNDING_VALUE - FEE, mining_script)],
                             fixture["transaction_version"], fixture["input_sequence"])
        for key, value in fixture["transaction"].items():
            if tx[key] != value:
                raise RuntimeError(f"Rust/Python transaction {key} differs in {name}")
        validate_witness(fixture, witness, tx["witness_bytes"])
        if (fixture["local_consensus"]["accepted"] is not True or
                fixture["local_policy"]["accepted"] is not True or
                fixture["input_sequence"] & 0xffff != CSV_UNITS):
            raise RuntimeError(f"The leaf or sequence changed in {name}")
        rows[name] = {"fixture": fixture, "transaction": tx}
    return rows


def run(node, manifest, report):
    address = manifest["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    if mining_script.hex() != manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and Rust disagree on destination script")
    hashes = []
    for _ in range(101):
        tick_512(node)
        hashes.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == mining_script.hex())
    outputs = [(FUNDING_VALUE, bytes.fromhex(row["script_pubkey_hex"]))
               for row in manifest["fixtures"]]
    outputs.append((5_000_000_000 - len(outputs) * FUNDING_VALUE - FEE, mining_script))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding txid mismatch")
    tick_512(node)
    funding_hash = node.rpc("generatetoaddress", 1, address)[0]
    funding_header = node.rpc("getblockheader", funding_hash)
    funding_height = funding_header["height"]
    funding_parent_hash = funding_header["previousblockhash"]
    funding_parent_header = node.rpc("getblockheader", funding_parent_hash)
    if funding_parent_header["height"] != funding_height - 1:
        raise RuntimeError("Funding parent height differs")
    if funding_header["time"] - funding_parent_header["time"] != SECONDS_PER_UNIT:
        raise RuntimeError("Funding block broke the 512-second mined-block cadence")
    funding_parent_mtp = funding_parent_header["mediantime"]
    funded, digest = generate(funding["txid"])
    validate_funded_manifest(manifest, funded, funding["txid"])
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    resolved = interpreter_provenance(funded, metadata)
    if resolved["source"] != funded["local_interpreter"]["source"]:
        raise RuntimeError("Resolved interpreter differs from generator provenance")
    rows = selected_transactions(funded, funding["txid"], mining_script)
    report.update({"funding_transaction": funding, "funded_fixture_sha256": digest,
                   "resolved_interpreter": resolved, "funding_block_hash": funding_hash,
                   "funding_height": funding_height, "funding_block_time": funding_header["time"],
                   "funding_parent_hash": funding_parent_hash,
                   "funding_parent_mtp": funding_parent_mtp})

    # At tip F+3, the next block is F+4 and parent MTP is base+4*512.
    for _ in range(3):
        tick_512(node)
        node.rpc("generatetoaddress", 1, address)
    before = snapshot(node, funding_height, funding_parent_mtp)
    if (before["height_since_funding"] != CSV_UNITS - 1 or
            before["mtp_since_funding_parent"] != (CSV_UNITS - 1) * SECONDS_PER_UNIT or
            before["tip_time"] - funding_header["time"] != 3 * SECONDS_PER_UNIT):
        raise RuntimeError(f"Immature boundary is not exact: {before}")
    report["immature_context"] = before
    for name, item in rows.items():
        tx = item["transaction"]
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if not maturity_rejection_matches(policy, tx["txid"], policy=True):
            raise RuntimeError(f"Unexpected immature policy result for {name}: {policy}")
        consensus = rejected_consensus_probe(node, address, tx)
        local = local_probe(tx, funding_height, funding_parent_mtp,
                            before["candidate_height"], before["candidate_parent_mtp"])
        missing_context = local_probe(tx, None, None, None, None)
        item["immature"] = {"context": before, "core": {"consensus": consensus, "policy": policy},
                             "local_sequence_lock": local,
                             "local_without_chain_context": missing_context}

    # At tip F+4, the next block is F+5 and parent MTP equals base+5*512.
    tick_512(node)
    node.rpc("generatetoaddress", 1, address)
    exact = snapshot(node, funding_height, funding_parent_mtp)
    if (exact["height_since_funding"] != CSV_UNITS or
            exact["mtp_since_funding_parent"] != CSV_UNITS * SECONDS_PER_UNIT or
            exact["tip_time"] - funding_header["time"] != 4 * SECONDS_PER_UNIT):
        raise RuntimeError(f"Mature boundary is not exact: {exact}")
    report["mature_context"] = exact
    for name, item in rows.items():
        tx = item["transaction"]
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if (policy.get("allowed") is not True or policy.get("txid") != tx["txid"] or
                policy.get("wtxid") != tx["wtxid"]):
            raise RuntimeError(f"Mature policy result differs for {name}: {policy}")
        local = local_probe(tx, funding_height, funding_parent_mtp,
                            exact["candidate_height"], exact["candidate_parent_mtp"])
        item["mature"] = {"context": exact, "core": {"policy": policy},
                           "local_sequence_lock": local}
    tick_512(node)
    result = node.rpc("generateblock", address,
                      [item["transaction"]["hex"] for item in rows.values()])
    block = node.rpc("getblock", result["hash"])
    if (block["height"] != exact["candidate_height"] or
            block["time"] - exact["tip_time"] != SECONDS_PER_UNIT or
            not all(item["transaction"]["txid"] in block["tx"] for item in rows.values())):
        raise RuntimeError("Mature block omitted a fixture or used the wrong height")
    for name, item in rows.items():
        item["mature"]["core"]["consensus"] = {
            "accepted": True, "block_hash": result["hash"], "block_height": block["height"]}
        report["results"].append({"name": name,
            "transaction": item["transaction"],
            "metrics": item["fixture"]["metrics"],
            "local_leaf_consensus": item["fixture"]["local_consensus"],
            "local_leaf_policy": item["fixture"]["local_policy"],
            "immature": item["immature"], "mature": item["mature"],
            "evidence": "differentially-validated",
            "deployment_at_immature_context": "consensus-incompatible",
            "deployment_at_mature_context": "policy-validated"})


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-bip68-maturity" or
            report.get("fixture_count") != len(NAMES) or
            len(report["results"]) != len(NAMES) or
            {row.get("name") for row in report["results"]} != set(NAMES)):
        return False
    for row in report["results"]:
        if (row["local_leaf_consensus"].get("accepted") is not True or
                row["local_leaf_policy"].get("accepted") is not True or
                row["immature"]["local_sequence_lock"].get("verdict") != "premature" or
                row["mature"]["local_sequence_lock"].get("verdict") != "mature" or
                row["immature"]["local_without_chain_context"].get("verdict") != "unsupported" or
                not maturity_rejection_matches(row["immature"]["core"]["consensus"],
                                               row["transaction"]["txid"]) or
                not maturity_rejection_matches(row["immature"]["core"]["policy"],
                                               row["transaction"]["txid"], policy=True) or
                row["mature"]["core"]["consensus"].get("accepted") is not True or
                row["mature"]["core"]["policy"].get("allowed") is not True):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/tapscript-maturity-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-bip68-maturity",
              "fixture_count": len(NAMES), "results": [],
              "initial_mocktime": START_TIME, "block_spacing_seconds": SECONDS_PER_UNIT,
              "bip68_sequence_units": CSV_UNITS,
              "consensus_method": "generateblock with funded raw transactions",
              "policy_method": "testmempoolaccept with -acceptnonstdtxn=0; Core v30.3 defaults",
              "scope": "Confirmed single-input Taproot CSV height/time spends at exact BIP68 funding-height and parent-MTP boundaries. Local leaf and sequence-lock results are distinct; Core validates complete transactions."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        manifest, digest = generate()
        if (manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
                manifest["expected_bitcoin_core_commit"] != RELEASE["commit"] or
                manifest["funding_value_sat"] != FUNDING_VALUE or manifest["fee_sat"] != FEE):
            raise RuntimeError("Generator oracle or funding configuration differs")
        report.update({key: value for key, value in manifest.items()
                       if key not in {"fixtures", "funding_txid", "experiment",
                                      "schema_version", "fixture_count"}})
        report.update({"bitcoin_core": provenance, "manifest_sha256": digest,
                       "source_manifest_experiment": manifest["experiment"],
                       "source_manifest_fixture_count": manifest["fixture_count"]})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-maturity-") as directory:
            node = Node(binary, Path(directory))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot", "csv")):
                    raise RuntimeError("Required consensus deployments inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot", "csv"]
                run(node, manifest, report)
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
