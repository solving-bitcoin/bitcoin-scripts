#!/usr/bin/env python3
"""Fund raw legacy boundary vectors on a fresh, isolated Core regtest chain.

No production wallet or network is used. This tests a DER parser gate and a
same-signature counterexample, not a covenant and not a mined new PoW.
Raw bytecode is intentional: these are exact consensus-boundary vectors, not
repository Script generators or optimized primitive measurements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from core_regtest import Node, RELEASE, consensus_check, transaction, vector
from legacy_same_signature_counterexample import make_vector


def push(data):
    if not data:
        return b"\x00"
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b"\x4c" + bytes([len(data)]) + data
    raise ValueError("fixture push too large")


def p2sh(script):
    return b"\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(script).digest()).digest() + b"\x87"


def legacy_tx(txid, vout, script_sig, output_script):
    raw = (struct.pack("<I", 2) + b"\x01" + bytes.fromhex(txid)[::-1]
           + struct.pack("<I", vout) + vector(script_sig) + b"\xff" * 4
           + b"\x01" + struct.pack("<Q", 990000) + vector(output_script)
           + b"\x00" * 4)
    return {"hex": raw.hex(),
            "txid": hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(),
            "weight": 4 * len(raw), "total_bytes": len(raw), "witness_bytes": 0,
            "script_sig_bytes": len(script_sig)}


def isolated_core_binary(cache, download):
    """Use the repository's archive pin; even -version gets an isolated datadir."""
    spec = RELEASE["archives"][f"{platform.system()}-{platform.machine()}"]
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / spec["filename"]
    if not archive.exists():
        if not download:
            raise RuntimeError("Pinned archive absent; use --download-core once")
        with urllib.request.urlopen(RELEASE["base_url"] + spec["filename"], timeout=60) as response:
            contents = response.read()
        assert hashlib.sha256(contents).hexdigest() == spec["sha256"]
        archive.write_bytes(contents)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == spec["sha256"]
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember(f"bitcoin-{RELEASE['version']}/bin/bitcoind")
        assert member.isfile()
        executable = bundle.extractfile(member).read()
    binary = cache / "bitcoind"
    binary.write_bytes(executable)
    binary.chmod(0o755)
    version = subprocess.check_output([str(binary), f"-datadir={cache}", "-nosettings", "-version"], text=True).splitlines()[0]
    assert version == f"Bitcoin Core daemon version v{RELEASE['version']}.0 bitcoind"
    return binary, {"version": RELEASE["version"], "commit": RELEASE["commit"],
                    "version_string": version, "archive": spec["filename"],
                    "archive_sha256": spec["sha256"], "binary_sha256": hashlib.sha256(executable).hexdigest(),
                    "checksums_url": RELEASE["checksums_url"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path("/private/tmp/covenant-core-30.3"))
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    binary, provenance = isolated_core_binary(args.cache_dir, args.download_core)
    preimage = bytes.fromhex("00000000000000000200a8013bbb8678")
    digest = hashlib.sha256(preimage).digest()
    assert digest.hex() == "301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302"
    hash_gate = bytes.fromhex("a800ac91")  # SHA256 0 CHECKSIG NOT
    parser_gate = bytes.fromhex("8201208800ac91")  # SIZE 32 EQUALVERIFY 0 CHECKSIG NOT
    same_signature = bytes.fromhex("6eadabac")
    malformed = bytes([0x31]) + digest[1:]
    negative_r = bytearray(digest)
    negative_r[4] |= 128
    zero_r = bytes.fromhex("301d0201000218") + b"\x01" + b"\x00" * 23 + b"\x01"
    assert len(zero_r) == 32
    fixtures = [
        ("hash-known-polyglot", hash_gate, preimage, True),
        ("hash-mutated-preimage", hash_gate, preimage + b"\x00", False),
        ("parser-known-polyglot", parser_gate, digest, True),
        ("parser-wrong-sequence-tag", parser_gate, malformed, False),
        ("parser-negative-r", parser_gate, bytes(negative_r), False),
        ("parser-empty-signature", parser_gate, b"", False),
        ("parser-zero-r-der-valid", parser_gate, zero_r, True),
        ("parser-undefined-hashtype", parser_gate, digest[:-1] + b"\x00", True),
        ("same-signature-two-contexts", same_signature, None, True),
    ]
    report = {"question": "Can legacy CHECKSIG failure expose DER syntax without EC recovery?",
              "bitcoin_core": provenance, "scope": "Complete P2SH spends of raw boundary vectors; no new PoW mined, no output covenant.",
              "results": []}
    with tempfile.TemporaryDirectory(prefix="covenant-core-check-") as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc("decodescript", "51")["segwit"]["address"]
            mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
            hashes = []
            for _ in range(101):
                node.tick()
                hashes += node.rpc("generatetoaddress", 1, address)
            coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
            coin = next(o for o in coinbase["vout"] if o["scriptPubKey"]["hex"] == mining_script.hex())
            outputs = [(1000000, p2sh(f[1])) for f in fixtures]
            outputs.append((5000000000 - 1000000 * len(fixtures) - 10000, mining_script))
            funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
            assert node.rpc("sendrawtransaction", funding["hex"]) == funding["txid"]
            node.tick()
            node.rpc("generatetoaddress", 1, address)
            report["funding_txid"] = funding["txid"]
            for index, (name, script, data, expected) in enumerate(fixtures):
                # Check alternative recipients against the SAME funded outpoint.
                recipients = [bytes.fromhex("0014") + bytes([byte]) * 20
                              for byte in ([0x11, 0x22] if name in ("hash-known-polyglot", "same-signature-two-contexts") else [0x11])]
                for output_script in recipients:
                    crypto_vector = None
                    if data is None:
                        crypto_vector = make_vector(name, output_script, outpoint_txid=funding["txid"], outpoint_vout=index, p2sh=True)
                        crypto_vector["redeemscript_hex"] = crypto_vector.pop("script_pubkey")
                        crypto_vector["redeemscript_bytes"] = crypto_vector.pop("locking_script_bytes")
                        crypto_vector["script_pubkey_hex"] = p2sh(script).hex()
                        crypto_vector["locking_script_bytes"] = 23
                        entry = [bytes.fromhex(crypto_vector["same_signature"]), bytes.fromhex(crypto_vector["same_public_key"])]
                    else:
                        entry = [data]
                    script_sig = b"".join(push(item) for item in entry) + push(script)
                    spend = legacy_tx(funding["txid"], index, script_sig, output_script)
                    if crypto_vector:
                        assert crypto_vector["spending_transaction_hex"] == spend["hex"]
                    decoded = node.rpc("decoderawtransaction", spend["hex"])
                    assert decoded["txid"] == spend["txid"] and decoded["weight"] == spend["weight"]
                    policy = node.rpc("testmempoolaccept", [spend["hex"]])[0]
                    consensus = consensus_check(node, address, spend)
                    assert consensus["accepted"] == expected, (name, consensus)
                    assert not policy["allowed"], (name, policy)
                    row = {"name": name, "recipient_script": output_script.hex(),
                           "redeemscript_hex": script.hex(), "redeemscript_bytes": len(script),
                           "locking_script_bytes": 23, "input_data_items": len(entry),
                           "hint_items": 0, "redeem_entry_items": len(entry),
                           "script_sig_push_items": len(entry) + 1,
                           "combined_stack_peak_by_inspection": 3 if data is not None else 4,
                           "static_non_push_opcodes_redeem": {hash_gate: 3, parser_gate: 4, same_signature: 4}[script],
                           "executed_non_push_opcodes_redeem_if_success": {hash_gate: 3, parser_gate: 4, same_signature: 4}[script] if expected else None,
                           "transaction": spend, "consensus": consensus, "policy": policy,
                           "evidence": "locally-reproduced",
                           "deployment_class": "consensus-validated" if expected else "consensus-incompatible"}
                    if crypto_vector:
                        row["crypto_vector"] = crypto_vector
                        row["evidence"] = "differentially-validated"
                    report["results"].append(row)
                    print(f"PASS {name} recipient={output_script[-1]:02x}: consensus={expected}, policy=False")
                    if consensus["accepted"]:
                        node.rpc("invalidateblock", consensus["block_hash"])
            report["all_expectations_met"] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
