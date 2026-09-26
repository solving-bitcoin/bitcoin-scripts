#!/usr/bin/env python3
"""Compare funded five-byte CHECKSEQUENCEVERIFY witnesses with pinned Core."""

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                          compact_size, consensus_check, core_binary,
                          interpreter_provenance, sha256, transaction, vector)

GENERATOR = "tapscript_csv_fixtures"
CORE_ERRORS = {
    "unsatisfied-locktime": "Locktime requirement not satisfied",
    "negative-locktime": "Negative locktime",
    "minimaldata": "unknown error",
    "numeric-overflow": "unknown error",
}
LOCAL_ERRORS = {
    "unsatisfied-locktime": "UnsatisfiedLocktime",
    "negative-locktime": "NegativeLocktime",
    "minimaldata": "MinimalData",
    "numeric-overflow": "ScriptIntNumericOverflow",
}


def generate(funding_txid=None):
    command = ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR]
    if funding_txid is not None:
        command.extend(["--", "--funding-txid", funding_txid])
    raw = subprocess.check_output(command, cwd=ROOT)
    return json.loads(raw), sha256(raw)


def csv_transaction(txid, vout, witness, outputs, version, sequence):
    """Independently serialize a version/sequence-parametrized one-input spend."""
    if version not in (1, 2) or not 0 <= sequence <= 0xffffffff:
        raise ValueError("Unsupported fixture transaction context")
    prefix = struct.pack("<I", version)
    txin = (compact_size(1) + bytes.fromhex(txid)[::-1] + struct.pack("<I", vout)
            + b"\x00" + struct.pack("<I", sequence))
    txout = compact_size(len(outputs)) + b"".join(struct.pack("<Q", value) + vector(script)
                                                  for value, script in outputs)
    base = prefix + txin + txout + b"\x00" * 4
    witness_bytes = compact_size(len(witness)) + b"".join(vector(item) for item in witness)
    raw = prefix + b"\x00\x01" + txin + txout + witness_bytes + b"\x00" * 4
    digest = lambda data: hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()
    weight = len(base) * 3 + len(raw)
    return {"hex": raw.hex(), "txid": digest(base), "wtxid": digest(raw), "weight": weight,
            "vsize": (weight + 3) // 4, "base_bytes": len(base), "total_bytes": len(raw),
            "witness_bytes": len(witness_bytes)}


def rejection_matches(result, category, policy=False):
    accepted = result["allowed"] if policy else result["accepted"]
    if category is None:
        return accepted
    if accepted:
        return False
    error = CORE_ERRORS[category]
    if policy:
        return result.get("reject-reason") == f"mempool-script-verify-flag-failed ({error})"
    return result.get("reason", "").startswith(
        f"TestBlockValidity failed: block-script-verify-flag-failed ({error}), input 0 of ")


def compare_local(fixture, core, profile):
    local = fixture[f"local_{profile}"]
    category = fixture["expected"][f"{profile}_rejection"]
    expected_error = LOCAL_ERRORS.get(category)
    has_verdict = local.get("outcome") == "executed" and type(local.get("accepted")) is bool
    core_accepted = core["accepted" if profile == "consensus" else "allowed"]
    matches = has_verdict and local["accepted"] == core_accepted and local.get("error") == expected_error
    return {"has_verdict": has_verdict, "expected_error": expected_error,
            "matches_core": matches,
            "status": "matched" if matches else "mismatch" if has_verdict else "no-verdict"}


def run_passed(report, allow_local_mismatches):
    return ("infrastructure_error" not in report and report["all_core_expectations_met"] and
            (report["all_local_consensus_comparisons_matched"] and
             report["all_local_policy_comparisons_matched"] or allow_local_mismatches))


def validate_funded_manifest(manifest, funded, funding_txid):
    if funded.get("funding_txid") != funding_txid:
        raise RuntimeError("Funded fixture outpoint differs from confirmed funding")
    for key, value in manifest.items():
        if key not in {"funding_txid", "fixtures"} and funded.get(key) != value:
            raise RuntimeError(f"Generator metadata changed after funding: {key}")
    if len(manifest["fixtures"]) != len(funded["fixtures"]):
        raise RuntimeError("Fixture count changed after funding")
    for commitment, signed in zip(manifest["fixtures"], funded["fixtures"]):
        for key, value in commitment.items():
            if signed.get(key) != value:
                raise RuntimeError(f"Funded fixture changed its commitment: {key}")


def validate_witness(fixture, witness, size):
    metric = fixture["metrics"]
    data = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
    if len(data) != 1 or witness != data + [bytes.fromhex(fixture["script_hex"]),
                                            bytes.fromhex(fixture["control_block_hex"])]:
        raise RuntimeError("Complete witness differs from committed script/data/control")
    if (metric["data_items"] != 1 or metric["taproot_witness_items"] != 3 or
            metric["hint_items"] != 0 or fixture["hint_items"] != 0):
        raise RuntimeError("Data, complete witness or zero-hint item count differs")
    data_size = len(compact_size(1)) + len(vector(data[0]))
    if (metric["data_witness_bytes"] != data_size or metric["taproot_witness_bytes"] != size or
            metric["locking_script_bytes"] != len(witness[-2]) or
            metric["control_block_bytes"] != len(witness[-1]) or
            metric["initial_validation_weight"] != 50 + size):
        raise RuntimeError("Independent serialized size or budget differs")
    for profile in ("consensus", "policy"):
        local = fixture[f"local_{profile}"]
        if local["outcome"] == "executed" and (local["stats"]["initial_validation_weight"] != 50 + size or
                local["stats"]["remaining_validation_weight"] != 50 + size):
            raise RuntimeError("CSV-only leaf changed signature budget or initial accounting")
    if metric["stack_peak"] != fixture["local_consensus"]["stats"]["combined_stack_peak"]:
        raise RuntimeError("Combined stack peak differs")


def run(node, manifest, report):
    address = manifest["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    if mining_script.hex() != manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and Rust disagree on destination script")
    hashes = []
    for _ in range(101):
        node.tick()
        hashes.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"] if output["scriptPubKey"]["hex"] == mining_script.hex())
    outputs = [(FUNDING_VALUE, bytes.fromhex(row["script_pubkey_hex"])) for row in manifest["fixtures"]]
    outputs.append((5_000_000_000 - len(outputs) * FUNDING_VALUE - FEE, mining_script))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding txid mismatch")
    node.tick()
    node.rpc("generatetoaddress", 1, address)
    # All positive lock-time cases need their funded output to be old enough
    # for BIP68 height and median-time rules; CSV script failures remain separate.
    for _ in range(16):
        node.tick()
        node.rpc("generatetoaddress", 1, address)
    funded, digest = generate(funding["txid"])
    validate_funded_manifest(manifest, funded, funding["txid"])
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    resolved = interpreter_provenance(funded, metadata)
    if resolved["source"] != funded["local_interpreter"]["source"]:
        raise RuntimeError("Resolved interpreter differs from generator provenance")
    report.update({"funding_transaction": funding, "funded_fixture_sha256": digest,
                   "resolved_interpreter": resolved, "maturity_blocks_after_funding": 16})
    for index, fixture in enumerate(funded["fixtures"]):
        if fixture["funding_vout"] != index:
            raise RuntimeError("Fixture order differs from funding output index")
        witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
        witness.extend([bytes.fromhex(fixture["script_hex"]), bytes.fromhex(fixture["control_block_hex"])])
        python_tx = csv_transaction(funding["txid"], index, witness,
                                    [(FUNDING_VALUE - FEE, mining_script)],
                                    fixture["transaction_version"], fixture["input_sequence"])
        for key, value in fixture["transaction"].items():
            if python_tx[key] != value:
                raise RuntimeError(f"Rust/Python transaction {key} differs in {fixture['name']}")
        validate_witness(fixture, witness, python_tx["witness_bytes"])
        decoded = node.rpc("decoderawtransaction", python_tx["hex"])
        for core_key, key in [("txid", "txid"), ("hash", "wtxid"), ("size", "total_bytes"),
                              ("vsize", "vsize"), ("weight", "weight")]:
            if decoded[core_key] != python_tx[key]:
                raise RuntimeError(f"Core decoded transaction {key} differs in {fixture['name']}")
        policy = node.rpc("testmempoolaccept", [python_tx["hex"]])[0]
        if policy.get("txid") != python_tx["txid"] or policy.get("wtxid") != python_tx["wtxid"] or "allowed" not in policy:
            raise RuntimeError("Incomplete or unrelated policy result")
        consensus = consensus_check(node, address, python_tx)
        expected = fixture["expected"]
        core_matches = (consensus["accepted"] == expected["consensus"] and
                        policy["allowed"] == expected["policy"] and
                        rejection_matches(consensus, expected["consensus_rejection"]) and
                        rejection_matches(policy, expected["policy_rejection"], policy=True))
        local_consensus = compare_local(fixture, consensus, "consensus")
        local_policy = compare_local(fixture, policy, "policy")
        report["results"].append({**fixture, "transaction": python_tx,
            "core": {"consensus": consensus, "policy": policy},
            "core_matches_expected": core_matches,
            "local_consensus_comparison": local_consensus,
            "local_policy_comparison": local_policy,
            "evidence": "differentially-validated",
            "deployment": "policy-validated" if policy["allowed"] else "consensus-validated" if consensus["accepted"] else "consensus-incompatible"})
        print(f"{'PASS' if core_matches and local_consensus['matches_core'] and local_policy['matches_core'] else 'DIFF'} {fixture['name']}: Core consensus={consensus['accepted']} policy={policy['allowed']} local={local_consensus['status']}/{local_policy['status']}", file=sys.stderr)
    report["all_core_expectations_met"] = all(row["core_matches_expected"] for row in report["results"])
    report["all_local_consensus_comparisons_matched"] = all(row["local_consensus_comparison"]["matches_core"] for row in report["results"])
    report["all_local_policy_comparisons_matched"] = all(row["local_policy_comparison"]["matches_core"] for row in report["results"])
    report["local_consensus_mismatch_count"] = sum(not row["local_consensus_comparison"]["matches_core"] for row in report["results"])
    report["local_policy_mismatch_count"] = sum(not row["local_policy_comparison"]["matches_core"] for row in report["results"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/tapscript-csv-v30.3.json")
    parser.add_argument("--allow-local-mismatches", action="store_true", help="record diagnostic local disagreements; Core expectations remain mandatory")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-tapscript-csv-five-byte", "results": [],
              "allow_local_mismatches": args.allow_local_mismatches, "all_core_expectations_met": False,
              "all_local_consensus_comparisons_matched": False, "all_local_policy_comparisons_matched": False}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        manifest, digest = generate()
        if (manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
                manifest["expected_bitcoin_core_commit"] != RELEASE["commit"] or
                manifest["funding_value_sat"] != FUNDING_VALUE or manifest["fee_sat"] != FEE):
            raise RuntimeError("Generator oracle or funding configuration differs")
        report.update({key: value for key, value in manifest.items() if key not in {"fixtures", "funding_txid"}})
        report.update({"bitcoin_core": provenance, "manifest_sha256": digest,
                       "initial_mocktime": START_TIME,
                       "consensus_method": "generateblock with funded raw transactions",
                       "policy_method": "testmempoolaccept with -acceptnonstdtxn=0; Core v30.3 defaults",
                       "scope": "Exact funded Taproot script-path CSV operands with complete transaction/prevout context. Local leaf execution uses strict resource limits, but Core alone checks commitment, BIP68 finality and relay policy."})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-csv-") as directory:
            node = Node(binary, Path(directory))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot")):
                    raise RuntimeError("Required consensus deployments inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot"]
                run(node, manifest, report)
            finally:
                node.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    report["run_passed"] = run_passed(report, args.allow_local_mismatches)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if report["run_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
