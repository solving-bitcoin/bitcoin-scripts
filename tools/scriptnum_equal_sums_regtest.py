#!/usr/bin/env python3
"""Compare exact wide-ScriptNum equality leaves against hash-pinned Core."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, ROOT, Node, consensus_check,
                          core_binary, sha256, transaction)


def compare(node, manifest):
    address = manifest["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    blocks = []
    for _ in range(101):
        node.tick()
        blocks.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", blocks[0], 2)["tx"][0]
    coin = next(v for v in coinbase["vout"] if v["scriptPubKey"]["hex"] == mining_script.hex())
    outputs = [(FUNDING_VALUE, bytes.fromhex(case["script_pubkey"])) for case in manifest["fixtures"]]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"],
                          outputs + [(5_000_000_000 - len(outputs) * FUNDING_VALUE - FEE, mining_script)])
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction id differs from the serialized transaction")
    node.tick()
    node.rpc("generatetoaddress", 1, address)

    results = []
    for index, case in enumerate(manifest["fixtures"]):
        witness = [bytes.fromhex(item) for item in case["witness"]]
        spend = transaction(funding["txid"], index, witness, [(FUNDING_VALUE - FEE, mining_script)])
        policy = node.rpc("testmempoolaccept", [spend["hex"]])[0]
        if policy.get("txid") != spend["txid"] or policy.get("wtxid") != spend["wtxid"]:
            raise RuntimeError(f"Policy verdict refers to a different spend: {case['name']}")
        consensus = consensus_check(node, address, spend)
        if policy["allowed"] is False and not policy["reject-reason"].startswith(
                "mempool-script-verify-flag-failed ("):
            raise RuntimeError(f"Expected a script rejection, got {policy}")
        core = [consensus["accepted"], policy["allowed"]]
        local = [verdict["accepted"] for verdict in case["local"]]
        expected_local = [True, True] if case["name"] == "numeric-negative" else case["expected"]
        results.append({
            "name": case["name"], "local": case["local"],
            "consensus": consensus, "policy": policy,
            "script_sha256": sha256(witness[-2]), "wtxid": spend["wtxid"],
            "complete_witness_items": len(witness), "data_items": len(witness) - 2,
            "hint_items": 0, "complete_witness_bytes": spend["witness_bytes"],
            "matches_expected": core == case["expected"] and local == expected_local,
        })
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/scriptnum-equal-sums.json")
    args = parser.parse_args()
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", "scriptnum_equal_sums_fixtures"],
        cwd=ROOT,
    )
    manifest = json.loads(raw)
    binary, core = core_binary(args.cache_dir.resolve(), args.download_core)
    with tempfile.TemporaryDirectory(prefix="bitcoin-lab-wide-sum-") as directory:
        node = Node(binary, Path(directory))
        try:
            node.ready()
            results = compare(node, manifest)
        finally:
            node.close()
    report = {
        "bitcoin_core": core, "compiler": manifest["compiler"],
        "interpreter": manifest["interpreter"], "manifest_sha256": sha256(raw),
        "node_options": node.options, "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for result in results:
        print(f"{'PASS' if result['matches_expected'] else 'FAIL'} {result['name']}")
    return 0 if all(row["matches_expected"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
