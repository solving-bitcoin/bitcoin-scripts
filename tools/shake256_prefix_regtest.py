#!/usr/bin/env python3
"""Validate the deterministic SHAKE256 prefix spend under Bitcoin Core."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import FEE, Node, START_TIME, consensus_check, core_binary, transaction

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true", help="allow first download of the pinned Core archive")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/ci-reports/shake256-prefix.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "all_expectations_met": False}
    try:
        fixture = json.loads(subprocess.check_output(
            ["cargo", "run", "--locked", "--quiet", "--example", "shake256_prefix_consensus_fixture"],
            cwd=ROOT,
        ))
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-shake256-") as temporary:
            node = Node(binary, Path(temporary))
            try:
                node.ready()
                address = fixture["mining_address"]
                mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
                hashes = []
                for _ in range(101):
                    node.tick()
                    hashes.extend(node.rpc("generatetoaddress", 1, address))
                coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
                coin = next(output for output in coinbase["vout"]
                            if output["scriptPubKey"]["hex"] == mining_script.hex())
                funding_value = 5_000_000_000 - FEE
                funding = transaction(coinbase["txid"], coin["n"], [b"\x51"],
                                      [(funding_value, bytes.fromhex(fixture["script_pubkey_hex"]))])
                if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
                    raise RuntimeError("funding transaction id mismatch")
                node.tick()
                node.rpc("generatetoaddress", 1, address)
                data_witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
                witness = data_witness + [bytes.fromhex(fixture["script_hex"]),
                                          bytes.fromhex(fixture["control_block_hex"])]
                spend = transaction(funding["txid"], 0, witness,
                                    [(funding_value - FEE, mining_script)])
                consensus = consensus_check(node, address, spend)
                report.update({
                    "bitcoin_core": provenance,
                    "fixture": {key: value for key, value in fixture.items()
                                if key not in {"script_hex", "data_witness_hex", "control_block_hex"}},
                    "transaction": {key: value for key, value in spend.items() if key != "hex"},
                    "core": {"consensus": consensus},
                    "evidence": "differentially-validated" if consensus["accepted"] else "locally-reproduced",
                    "deployment": "consensus-validated" if consensus["accepted"] else "consensus-incompatible",
                    "all_expectations_met": consensus["accepted"] == fixture["expected_consensus"],
                    "initial_mocktime": START_TIME,
                    "policy_claim": "not measured; this is a consensus-only generateblock check",
                })
                print(f"{'PASS' if report['all_expectations_met'] else 'FAIL'} SHAKE256 prefix: consensus={consensus['accepted']}", file=sys.stderr)
            finally:
                node.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if report["all_expectations_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
