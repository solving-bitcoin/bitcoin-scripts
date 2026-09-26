#!/usr/bin/env python3
"""Fund, sign and differentially validate the complete-witness tapscript signature-budget fixtures."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                          consensus_check, core_binary, interpreter_provenance, sha256, transaction)

GENERATOR = "tapscript_budget_fixtures"
CORE_ERRORS = {"validation-weight": "Too much signature validation relative to witness weight",
               "checksigverify": "Script failed an OP_CHECKSIGVERIFY operation"}
LOCAL_ERRORS = {"validation-weight": "TapscriptValidationWeight", "checksigverify": "CheckSigVerify"}


def generate(funding_txid=None):
    command = ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR]
    if funding_txid is not None:
        command.extend(["--", "--funding-txid", funding_txid])
    raw = subprocess.check_output(command, cwd=ROOT)
    return json.loads(raw), sha256(raw)


def rejection_matches(result, category, policy=False):
    accepted = result["allowed"] if policy else result["accepted"]
    if category is None:
        return accepted
    if accepted:
        return False
    if policy and category == "witness-nonstandard":
        return result.get("reject-reason") == "bad-witness-nonstandard"
    message = CORE_ERRORS[category]
    if policy:
        return result.get("reject-reason") == f"mempool-script-verify-flag-failed ({message})"
    return result.get("reason", "").startswith(
        f"TestBlockValidity failed: block-script-verify-flag-failed ({message}), input 0 of ")


def compare_local(fixture, consensus, field="local_full_witness"):
    local = fixture[field]
    has_verdict = local.get("outcome") == "executed" and type(local.get("accepted")) is bool
    error = LOCAL_ERRORS.get(fixture["expected"]["consensus_rejection"])
    matches = has_verdict and local["accepted"] == consensus["accepted"] and local.get("error") == error
    return {"has_verdict": has_verdict, "expected_error": error, "matches_consensus": matches,
            "status": "matched" if matches else "mismatch" if has_verdict else "no-verdict"}


def run_passed(report, allow_local_mismatches):
    return ("infrastructure_error" not in report and report["all_core_expectations_met"] and
            (report["all_local_consensus_comparisons_matched"] or allow_local_mismatches))


def validate_funded_manifest(manifest, funded, funding_txid):
    if funded.get("funding_txid") != funding_txid:
        raise RuntimeError("Funded fixture outpoint does not match the confirmed funding transaction")
    for key, value in manifest.items():
        if key not in {"funding_txid", "fixtures"} and funded.get(key) != value:
            raise RuntimeError(f"Generator metadata changed after funding: {key}")
    if len(manifest["fixtures"]) != len(funded["fixtures"]):
        raise RuntimeError("Fixture count changed after funding")
    for commitment, signed in zip(manifest["fixtures"], funded["fixtures"]):
        for key, value in commitment.items():
            if signed.get(key) != value:
                raise RuntimeError(f"Funded fixture changed its commitment or expectations: {key}")


def validate_witness_counts(fixture, complete_witness):
    data_items = len(fixture["data_witness_hex"])
    annex_items = int(fixture.get("annex_hex") is not None)
    if (fixture["metrics"]["data_items"] != data_items
            or fixture["metrics"]["taproot_witness_items"] != data_items+2+annex_items
            or len(complete_witness) != data_items+2+annex_items):
        raise RuntimeError("Reported data/complete witness item counts differ from the serialized transaction")
    expected = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
    expected.extend([bytes.fromhex(fixture["script_hex"]), bytes.fromhex(fixture["control_block_hex"])])
    if annex_items:
        annex = bytes.fromhex(fixture["annex_hex"])
        if not annex or annex[0] != 0x50:
            raise RuntimeError("Malformed annex fixture")
        expected.append(annex)
    if complete_witness != expected:
        raise RuntimeError("Complete witness differs from data/script/control/annex commitments")
    if fixture["metrics"]["hint_items"] != 0 or fixture["hint_items"] != 0:
        raise RuntimeError("Budget experiment requires zero auxiliary hint items")


def validate_budget_metrics(fixture, full_witness_bytes):
    from core_regtest import compact_size, vector
    metrics = fixture["metrics"]
    data = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
    data_bytes = len(compact_size(len(data))) + sum(len(vector(item)) for item in data)
    if (metrics["data_witness_bytes"] != data_bytes
            or metrics["taproot_witness_bytes"] != full_witness_bytes
            or metrics["initial_full_witness_validation_weight"] != 50 + full_witness_bytes
            or metrics["initial_data_only_validation_weight"] != 50 + data_bytes
            or metrics["requested_validation_weight"] != 50 * fixture["nonempty_signature_checks"]
            or metrics["expected_remaining_if_all_checks_charged"] != 50 + full_witness_bytes - 50 * fixture["nonempty_signature_checks"]):
        raise RuntimeError("Budget metrics differ from independent full/data witness serialization")
    for field, expected in [("local_full_witness", 50 + full_witness_bytes), ("local_legacy_fragment", 50 + data_bytes)]:
        local = fixture[field]
        if local.get("outcome") == "executed" and local["stats"]["initial_validation_weight"] != expected:
            raise RuntimeError(f"{field} initial budget differs from the declared constructor boundary")
    local = fixture["local_full_witness"]
    if local.get("outcome") == "executed" and local["stats"]["remaining_validation_weight"] != metrics["expected_remaining_if_all_checks_charged"]:
        raise RuntimeError("Full-witness remaining budget differs from the boundary fixture")


def run(node, manifest, report):
    address = manifest["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    if mining_script.hex() != manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and Rust disagree on the destination script")
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
    funded, digest = generate(funding["txid"])
    validate_funded_manifest(manifest, funded, funding["txid"])
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    resolved = interpreter_provenance(funded, metadata)
    if resolved["source"] != funded["local_interpreter"]["source"]:
        raise RuntimeError("Compiled interpreter provenance differs from the resolved source")
    report.update({"funding_transaction": funding, "funded_fixture_sha256": digest,
                   "resolved_interpreter": resolved})
    for index, fixture in enumerate(funded["fixtures"]):
        if fixture["funding_vout"] != index:
            raise RuntimeError("Fixture order and funding output index differ")
        witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
        witness.extend([bytes.fromhex(fixture["script_hex"]), bytes.fromhex(fixture["control_block_hex"])])
        if fixture["annex_hex"] is not None:
            witness.append(bytes.fromhex(fixture["annex_hex"]))
        validate_witness_counts(fixture, witness)
        python_tx = transaction(funding["txid"], index, witness, [(FUNDING_VALUE-FEE, mining_script)])
        for key, value in fixture["transaction"].items():
            if python_tx[key] != value:
                raise RuntimeError(f"Rust/Python transaction {key} differs for {fixture['name']}")
        validate_budget_metrics(fixture, python_tx["witness_bytes"])
        decoded = node.rpc("decoderawtransaction", python_tx["hex"])
        for core_key, key in [("txid", "txid"), ("hash", "wtxid"), ("size", "total_bytes"), ("vsize", "vsize"), ("weight", "weight")]:
            if decoded[core_key] != python_tx[key]:
                raise RuntimeError(f"Core transaction {key} differs for {fixture['name']}")
        policy = node.rpc("testmempoolaccept", [python_tx["hex"]])[0]
        if policy.get("txid") != python_tx["txid"] or policy.get("wtxid") != python_tx["wtxid"] or "allowed" not in policy:
            raise RuntimeError("Incomplete or unrelated policy result")
        consensus = consensus_check(node, address, python_tx)
        expected = fixture["expected"]
        core_matches = (consensus["accepted"] == expected["consensus"] and policy["allowed"] == expected["policy"]
                        and rejection_matches(consensus, expected["consensus_rejection"])
                        and rejection_matches(policy, expected["policy_rejection"], policy=True))
        local = compare_local(fixture, consensus)
        legacy = compare_local(fixture, consensus, "local_legacy_fragment")
        row = {**fixture, "transaction": python_tx, "core": {"consensus": consensus, "policy": policy},
               "core_matches_expected": core_matches, "local_comparison": local, "legacy_fragment_comparison": legacy,
               "evidence": "differentially-validated",
               "deployment": "policy-validated" if policy["allowed"] else "consensus-validated" if consensus["accepted"] else "consensus-incompatible"}
        report["results"].append(row)
        print(f"{'PASS' if core_matches and local['matches_consensus'] else 'DIFF'} {fixture['name']}: Core consensus={consensus['accepted']} policy={policy['allowed']} local={local['status']} {fixture['local_full_witness']['error']} legacy={legacy['status']}", file=sys.stderr)
    report["all_core_expectations_met"] = all(row["core_matches_expected"] for row in report["results"])
    report["all_local_consensus_comparisons_matched"] = all(row["local_comparison"]["matches_consensus"] for row in report["results"])
    report["local_mismatch_count"] = sum(not row["local_comparison"]["matches_consensus"] for row in report["results"])
    report["legacy_fragment_mismatch_count"] = sum(not row["legacy_fragment_comparison"]["matches_consensus"] for row in report["results"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT/"target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT/"target/tapscript-budget-v30.3.json")
    parser.add_argument("--allow-local-mismatches", action="store_true", help="record a diagnostic local mismatch; Core expectations remain mandatory")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-tapscript-signature-budget", "results": [],
              "allow_local_mismatches": args.allow_local_mismatches, "all_core_expectations_met": False,
              "all_local_consensus_comparisons_matched": False}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        manifest, digest = generate()
        if (manifest["expected_bitcoin_core_version"] != RELEASE["version"] or manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]
                or manifest["funding_value_sat"] != FUNDING_VALUE or manifest["fee_sat"] != FEE):
            raise RuntimeError("Generator oracle/transaction configuration differs from runner")
        report.update({key: value for key, value in manifest.items() if key not in {"fixtures", "funding_txid"}})
        report.update({"bitcoin_core": provenance, "manifest_sha256": digest, "initial_mocktime": START_TIME,
                       "consensus_method": "generateblock with raw transactions and connected-block txid check",
                       "policy_method": "testmempoolaccept with -acceptnonstdtxn=0; Core v30.3 defaults",
                       "scope": "Exact funded Taproot spends at signature-budget boundaries, with valid known 32-byte public keys and real signatures. Complete-witness local constructor compared to Core consensus; legacy fragment constructor retained as a labeled counterexample. Core independently measures relay policy; annex and oversized data elements are nonstandard."})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-budget-") as temporary:
            node = Node(binary, Path(temporary))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot")):
                    raise RuntimeError("Required consensus deployments are inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot"]
                run(node, manifest, report)
            finally:
                node.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    passed = run_passed(report, args.allow_local_mismatches)
    report["run_passed"] = passed
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
