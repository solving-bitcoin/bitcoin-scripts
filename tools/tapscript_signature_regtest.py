#!/usr/bin/env python3
"""Fund, sign and differentially validate the standalone tapscript signature fixtures."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                          consensus_check, core_binary, interpreter_provenance, sha256, transaction)

GENERATOR = "tapscript_signature_fixtures"
CORE_ERRORS = {
    "schnorr-signature": "Invalid Schnorr signature",
    "schnorr-hashtype": "Invalid Schnorr signature hash type",
    "checksigverify": "Script failed an OP_CHECKSIGVERIFY operation",
    "tapscript-checkmultisig": "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
    "discourage-upgradeable-pubkey": "Public key version reserved for soft-fork upgrades",
}
LOCAL_ERRORS = {"schnorr-signature": "SchnorrSig", "schnorr-hashtype": "SchnorrSigHashtype",
                "checksigverify": "CheckSigVerify", "tapscript-checkmultisig": "TapscriptCheckMultiSig"}


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
    message = CORE_ERRORS[category]
    if policy:
        return result.get("reject-reason") == f"mempool-script-verify-flag-failed ({message})"
    return result.get("reason", "").startswith(
        f"TestBlockValidity failed: block-script-verify-flag-failed ({message}), input 0 of ")


def compare_local(fixture, consensus):
    local = fixture["local"]
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
    if (fixture["metrics"]["data_items"] != data_items
            or fixture["metrics"]["taproot_witness_items"] != data_items+2
            or len(complete_witness) != data_items+2):
        raise RuntimeError("Reported data/complete witness item counts differ from the serialized transaction")
    if fixture["metrics"]["hint_items"] != 0 or fixture["hint_items"] != 0:
        raise RuntimeError("Signature experiment requires zero auxiliary hint items")


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
        validate_witness_counts(fixture, witness)
        python_tx = transaction(funding["txid"], index, witness, [(FUNDING_VALUE-FEE, mining_script)])
        for key, value in fixture["transaction"].items():
            if python_tx[key] != value:
                raise RuntimeError(f"Rust/Python transaction {key} differs for {fixture['name']}")
        if python_tx["witness_bytes"] != fixture["metrics"]["taproot_witness_bytes"]:
            raise RuntimeError("Rust/Python full witness size differs")
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
        row = {**fixture, "transaction": python_tx, "core": {"consensus": consensus, "policy": policy},
               "core_matches_expected": core_matches, "local_comparison": local,
               "evidence": "differentially-validated",
               "deployment": "policy-validated" if policy["allowed"] else "consensus-validated" if consensus["accepted"] else "consensus-incompatible"}
        report["results"].append(row)
        print(f"{'PASS' if core_matches and local['matches_consensus'] else 'DIFF'} {fixture['name']}: Core consensus={consensus['accepted']} policy={policy['allowed']} local={local['status']} {fixture['local']['error']}", file=sys.stderr)
    report["all_core_expectations_met"] = all(row["core_matches_expected"] for row in report["results"])
    report["all_local_consensus_comparisons_matched"] = all(row["local_comparison"]["matches_consensus"] for row in report["results"])
    report["local_mismatch_count"] = sum(not row["local_comparison"]["matches_consensus"] for row in report["results"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT/"target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT/"target/tapscript-signatures-v30.3.json")
    parser.add_argument("--allow-local-mismatches", action="store_true", help="record an explicit historical baseline; Core expectations remain mandatory")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-tapscript-signature-semantics", "results": [],
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
                       "scope": "Exact funded Taproot spends; local consensus-oriented direct Exec with complete transaction and prevouts. No full local policy or signature-budget-boundary claim."})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-signatures-") as temporary:
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
