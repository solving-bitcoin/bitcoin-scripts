#!/usr/bin/env python3
"""Validate checked PRINCEv2 leaves with a pinned, isolated Bitcoin Core node.

Uses only the Python standard library and the shared Core download, RPC and
transaction primitives. The report covers exact funded spends, with separate
consensus and relay-policy checks; public test keys offer no authorization.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                         compact_size, consensus_check, core_binary, sha256,
                         transaction, vector)

GENERATOR = "prince_validation_fixtures"
EXPERIMENT = "checked-princev2-complete-taproot-leaves"
CORE_ERRORS = {
    "verify": "Script failed an OP_VERIFY operation",
    "equalverify": "Script failed an OP_EQUALVERIFY operation",
    "numequalverify": "Script failed an OP_NUMEQUALVERIFY operation",
    # Pinned Core maps numeric minimal-encoding exceptions to unknown error.
    "minimaldata": "unknown error",
}
LOCAL_ERRORS = {"verify": "Verify", "equalverify": "EqualVerify",
                "numequalverify": "NumEqualVerify", "minimaldata": "MinimalData"}


def rejection_matches(result, category, policy=False):
    accepted = result["allowed"] if policy else result["accepted"]
    if category is None:
        return accepted is True
    if accepted is not False:
        return False
    message = CORE_ERRORS[category]
    if policy:
        return result.get("reject-reason") == f"mempool-script-verify-flag-failed ({message})"
    return result.get("reason", "").startswith(
        f"TestBlockValidity failed: block-script-verify-flag-failed ({message}), input 0 of ")


def compare_local_profiles(fixture, consensus, policy):
    """Only completed interpreter verdicts with the expected error are comparable."""
    comparisons = {}
    for name, accepted in [("consensus", consensus["accepted"]), ("policy", policy["allowed"])]:
        local = fixture["local_profiles"][name]
        expected = fixture["expected"][name]
        category = fixture["expected"][f"{name}_rejection"]
        if type(expected) is not bool or expected != (category is None):
            raise RuntimeError("Expected verdict and rejection category are inconsistent")
        expected_error = LOCAL_ERRORS[category] if category else None
        has_verdict = local.get("outcome") == "executed" and type(local.get("accepted")) is bool
        matches = (has_verdict and local["accepted"] == accepted == expected
                   and local.get("error") == expected_error)
        comparisons[name] = {"has_verdict": has_verdict, "expected_error": expected_error,
                             "matches_core_and_expected": matches,
                             "status": "matched" if matches else "mismatch" if has_verdict else "no-verdict"}
    return {"profiles": comparisons, "all_matched": all(row["matches_core_and_expected"] for row in comparisons.values())}


def resolved_provenance(fixtures, metadata):
    result = {}
    for field, name in [("local_interpreter", "bitcoin-scriptexec"), ("compiler", "bitcoin-script")]:
        claimed = fixtures[field]
        packages = [package for package in metadata["packages"] if package["name"] == name]
        if len(packages) != 1:
            raise RuntimeError(f"Expected exactly one resolved {name} package")
        package = packages[0]
        for key in ("name", "version", "source"):
            if claimed.get(key) != package.get(key):
                raise RuntimeError(f"Compiled {name} {key} differs from Cargo's resolved graph")
        commit = claimed["commit"]
        source = package.get("source")
        if (not isinstance(commit, str) or len(commit) != 40
                or any(character not in "0123456789abcdef" for character in commit)
                or not isinstance(source, str) or not source.startswith("git+")
                or source.rpartition("#")[2] != commit):
            raise RuntimeError(f"Expected an immutable resolved git commit for {name}")
        result[field] = {key: package[key] for key in ("name", "version", "source")}
    return result


def validate_reference(fixtures, source_bytes):
    """Bind every fixture to the independently generated, pinned C oracle."""
    source = json.loads(source_bytes)
    reference = fixtures["cipher_reference"]
    if (reference["fixture_sha256"] != sha256(source_bytes)
            or reference["commit"] != source["commit"]
            or reference["source"] != source["source"]
            or source["commit"] != "0c6172dcd85f1fe6a269519093a79c7350fe6e55"):
        raise RuntimeError("Independent C reference provenance mismatch")
    if (fixtures.get("schema_version") != 1 or fixtures.get("experiment") != EXPERIMENT
            or fixtures["fixture_count"] != len(fixtures["fixtures"])
            or not fixtures["fixtures"]):
        raise RuntimeError("Unexpected or empty PRINCE fixture schema")
    names = [row["name"] for row in fixtures["fixtures"]]
    if len(names) != len(set(names)):
        raise RuntimeError("Duplicate fixture names")
    for row in fixtures["fixtures"]:
        upstream = source["vectors"][row["reference_vector_index"]]
        for key, reference_key in [("key_hex", "key"), ("reference_plaintext_hex", "plaintext"),
                                   ("reference_ciphertext_hex", "ciphertext")]:
            if row[key] != upstream[reference_key]:
                raise RuntimeError(f"PRINCE fixture differs from independent C vector: {row['name']} {key}")


def validate_witness(fixture, complete):
    metrics = fixture["metrics"]
    data = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
    script = bytes.fromhex(fixture["script_hex"])
    control = bytes.fromhex(fixture["control_block_hex"])
    serialized_size = lambda items: len(compact_size(len(items))) + sum(len(vector(item)) for item in items)
    if complete != data + [script, control]:
        raise RuntimeError("Full Taproot witness does not match declared data/script/control")
    if (metrics["data_items"] != len(data) or metrics["taproot_witness_items"] != len(data)+2
            or metrics["data_witness_bytes"] != serialized_size(data)
            or metrics["taproot_witness_bytes"] != serialized_size(complete)
            or metrics["locking_script_bytes"] != len(script)
            or fixture["script_sha256"] != sha256(script)):
        raise RuntimeError("Reported script/witness bytes or item counts differ from serialization")
    if metrics["hint_items"] != 0 or metrics["hint_bytes"] != 0:
        raise RuntimeError("PRINCE experiment requires zero auxiliary hints")
    if fixture["expected"]["consensus"] and (len(data) != 16 or len(complete) != 18):
        raise RuntimeError("Honest PRINCE leaves require 16 data and 18 full witness items")


def run_passed(report):
    return ("infrastructure_error" not in report and bool(report.get("results"))
            and report.get("all_core_expectations_met") is True
            and report.get("all_local_profile_comparisons_matched") is True)


def run(node, fixtures, report):
    address = fixtures["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    hashes = []
    for _ in range(101):
        node.tick()
        hashes.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"] if output["scriptPubKey"]["hex"] == mining_script.hex())
    outputs = [(FUNDING_VALUE, bytes.fromhex(row["script_pubkey_hex"])) for row in fixtures["fixtures"]]
    outputs.append((5_000_000_000 - len(outputs)*FUNDING_VALUE - FEE, mining_script))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction id mismatch")
    node.tick()
    node.rpc("generatetoaddress", 1, address)
    report["funding_transaction"] = funding
    for index, fixture in enumerate(fixtures["fixtures"]):
        complete = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
        complete.extend([bytes.fromhex(fixture["script_hex"]), bytes.fromhex(fixture["control_block_hex"])])
        validate_witness(fixture, complete)
        tx = transaction(funding["txid"], index, complete, [(FUNDING_VALUE-FEE, mining_script)])
        if tx["witness_bytes"] != fixture["metrics"]["taproot_witness_bytes"]:
            raise RuntimeError("Transaction witness size mismatch")
        decoded = node.rpc("decoderawtransaction", tx["hex"])
        for core_key, key in [("txid", "txid"), ("hash", "wtxid"), ("size", "total_bytes"),
                               ("vsize", "vsize"), ("weight", "weight")]:
            if decoded[core_key] != tx[key]:
                raise RuntimeError(f"Core transaction {key} differs for {fixture['name']}")
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if policy.get("txid") != tx["txid"] or policy.get("wtxid") != tx["wtxid"] or "allowed" not in policy:
            raise RuntimeError("Incomplete or unrelated policy result")
        consensus = consensus_check(node, address, tx)
        expected = fixture["expected"]
        core_matches = (consensus["accepted"] == expected["consensus"] and policy["allowed"] == expected["policy"]
                        and rejection_matches(consensus, expected["consensus_rejection"])
                        and rejection_matches(policy, expected["policy_rejection"], policy=True))
        local = compare_local_profiles(fixture, consensus, policy)
        row = {**fixture, "transaction": tx, "core": {"consensus": consensus, "policy": policy},
               "core_matches_expected": core_matches, "local_profile_comparison": local,
               "evidence": "differentially-validated",
               "deployment": "policy-validated" if policy["allowed"] else "consensus-validated" if consensus["accepted"] else "consensus-incompatible"}
        report["results"].append(row)
        print(f"{'PASS' if core_matches and local['all_matched'] else 'FAIL'} {fixture['name']}: Core consensus={consensus['accepted']} policy={policy['allowed']} profiles={local['all_matched']}", file=sys.stderr)
    report["all_core_expectations_met"] = all(row["core_matches_expected"] for row in report["results"])
    report["all_local_profile_comparisons_matched"] = all(row["local_profile_comparison"]["all_matched"] for row in report["results"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true", help="allow first download of the hash-pinned Core archive")
    parser.add_argument("--cache-dir", type=Path, default=ROOT/"target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT/"target/prince-validation-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": EXPERIMENT, "results": [],
              "all_core_expectations_met": False, "all_local_profile_comparisons_matched": False}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        raw = subprocess.check_output(["cargo", "run", "--locked", "--quiet", "--example", GENERATOR], cwd=ROOT)
        fixtures = json.loads(raw)
        if (fixtures["expected_bitcoin_core_version"] != RELEASE["version"]
                or fixtures["expected_bitcoin_core_commit"] != RELEASE["commit"]):
            raise RuntimeError("Fixture oracle pin differs from binary manifest")
        validate_reference(fixtures, (ROOT/"tests/data/princev2_upstream_vectors.json").read_bytes())
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
        resolved = resolved_provenance(fixtures, metadata)
        report.update({key: value for key, value in fixtures.items() if key != "fixtures"})
        report.update({"bitcoin_core": provenance, "fixture_sha256": sha256(raw),
                       "resolved_dependencies": resolved, "initial_mocktime": START_TIME,
                       "consensus_method": "generateblock with raw transactions and connected-block txid check",
                       "policy_method": "testmempoolaccept with -acceptnonstdtxn=0; Core v30.3 defaults",
                       "scope": "Exact complete funded Taproot spends and supported local script profiles. Tested PRINCE keys/blocks only; no general key-independent deployment, transaction authorization or secrecy claim."})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-prince-") as temporary:
            node = Node(binary, Path(temporary))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot")):
                    raise RuntimeError("Required consensus deployments are inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot"]
                run(node, fixtures, report)
            finally:
                node.close()
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    passed = run_passed(report)
    report["run_passed"] = passed
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
