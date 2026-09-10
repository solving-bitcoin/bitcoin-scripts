#!/usr/bin/env python3
"""Compare complete deterministic Taproot spends with a pinned, isolated Core node.

Standard-library only. Never connects to an existing node or uses a wallet.
The initial binary download requires --download-core; subsequent runs use the
hash-verified archive in target/core-regtest/. See knowledge/core-validation.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = json.loads((ROOT / "tools/bitcoin_core_release.json").read_text())
START_TIME = 1_800_000_000
FUNDING_VALUE = 1_000_000
FEE = 10_000
# Exact diagnostics from the pinned oracle. Core reports both numeric decoding
# failures as "unknown error"; the fixture mutation supplies their finer labels.
SCRIPT_ERRORS = {
    "stack-size": "Stack size limit exceeded",
    "push-size": "Push value size limit exceeded",
    "invalid-stack-operation": "Operation not valid with the current stack size",
    "equalverify": "Script failed an OP_EQUALVERIFY operation",
    "scriptnum-overflow": "unknown error",
    "minimaldata": "unknown error",
    "minimal-push": "Data push larger than necessary",
    "tapscript-minimal-if": "OP_IF/NOTIF argument must be minimal in tapscript",
    "discourage-op-success": "OP_SUCCESSx reserved for soft-fork upgrades",
    "bad-opcode": "Opcode missing or not understood",
    "eval-false": "Script evaluated without error but finished with a false/empty top stack element",
    "taproot-commitment": "Witness program hash mismatch",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def vector(data: bytes) -> bytes:
    return compact_size(len(data)) + data


def transaction(txid: str, vout: int, witness: list[bytes], outputs: list[tuple[int, bytes]]) -> dict:
    """Version-2, one-input transaction with empty scriptSig and final sequence."""
    version = struct.pack("<I", 2)
    txin = compact_size(1) + bytes.fromhex(txid)[::-1] + struct.pack("<I", vout) + b"\x00\xff\xff\xff\xff"
    txout = compact_size(len(outputs)) + b"".join(struct.pack("<Q", value) + vector(script) for value, script in outputs)
    locktime = b"\x00" * 4
    base = version + txin + txout + locktime
    witness_bytes = compact_size(len(witness)) + b"".join(vector(item) for item in witness)
    raw = version + b"\x00\x01" + txin + txout + witness_bytes + locktime
    digest = lambda data: hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()
    weight = len(base) * 3 + len(raw)
    return {"hex": raw.hex(), "txid": digest(base), "wtxid": digest(raw), "weight": weight,
            "vsize": (weight + 3) // 4, "base_bytes": len(base), "total_bytes": len(raw),
            "witness_bytes": len(witness_bytes)}


def core_binary(cache: Path, allow_download: bool) -> tuple[Path, dict]:
    target = f"{platform.system()}-{platform.machine()}"
    spec = RELEASE["archives"].get(target)
    if spec is None:
        raise RuntimeError(f"No pinned Core archive for {target}")
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / spec["filename"]
    if not archive.exists():
        if not allow_download:
            raise RuntimeError("Pinned Core archive is absent. Run once with --download-core.")
        print(f"Downloading pinned Bitcoin Core {RELEASE['version']} ({target})", file=sys.stderr)
        # Atomic replacement prevents an interrupted download poisoning the cache.
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
            partial = Path(output.name)
            try:
                with urllib.request.urlopen(RELEASE["base_url"] + spec["filename"], timeout=120) as source:
                    shutil.copyfileobj(source, output)
                output.close()
                if sha256(partial.read_bytes()) != spec["sha256"]:
                    raise RuntimeError("Downloaded Core archive checksum mismatch")
                partial.replace(archive)
            finally:
                partial.unlink(missing_ok=True)
    if sha256(archive.read_bytes()) != spec["sha256"]:
        raise RuntimeError(f"Cached Core archive checksum mismatch: {archive}")
    # Extract only the expected executable, never archive paths or symlinks.
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember(f"bitcoin-{RELEASE['version']}/bin/bitcoind")
        if not member.isfile():
            raise RuntimeError("Expected a regular bitcoind file in verified archive")
        source = bundle.extractfile(member)
        assert source is not None
        executable = source.read()
    binary = cache / "bitcoind"
    binary.write_bytes(executable)
    binary.chmod(0o755)
    version = subprocess.check_output([str(binary), "-version"], text=True).splitlines()[0]
    if version != f"Bitcoin Core daemon version v{RELEASE['version']}.0 bitcoind":
        raise RuntimeError(f"Unexpected binary version: {version}")
    return binary, {"version": RELEASE["version"], "commit": RELEASE["commit"], "version_string": version,
                    "archive": spec["filename"], "archive_sha256": spec["sha256"],
                    "binary_sha256": sha256(executable), "checksums_url": RELEASE["checksums_url"]}


class RPCError(RuntimeError):
    def __init__(self, error: dict):
        self.code = error["code"]
        self.message = error["message"]
        super().__init__(f"RPC {self.code}: {self.message}")


def rejection_matches(result: dict, category: str | None, policy: bool = False) -> bool:
    accepted = result["allowed"] if policy else result["accepted"]
    if category is None:
        return accepted
    if accepted:
        return False
    if policy and category == "witness-stack-item-size":
        return result.get("reject-reason") == "bad-witness-nonstandard"
    message = SCRIPT_ERRORS[category]
    if policy:
        return result.get("reject-reason") == f"mempool-script-verify-flag-failed ({message})"
    return result.get("reason", "").startswith(f"TestBlockValidity failed: block-script-verify-flag-failed ({message}), input 0 of ")


def compare_local_profiles(fixture: dict, consensus: dict, policy: dict) -> dict:
    """Require actual profile verdicts; None/panics must never resemble rejection."""
    comparison = fixture["local_profile_comparison"]
    compare_to_core = comparison["compare_to_core"]
    if type(compare_to_core) is not bool:
        raise ValueError("Local comparison mode must be boolean")
    if not compare_to_core and fixture["name"] != "winternitz-invalid-control-block":
        raise ValueError("Unexpected fixture excluded from local/Core comparison")
    results = {}
    for name, core in [("consensus", consensus["accepted"]), ("policy", policy["allowed"])]:
        local = fixture["local_profiles"][name]
        expected = comparison["expected"][name]
        if type(expected) is not bool:
            raise ValueError("Local profile expectation must be boolean")
        has_verdict = (type(local.get("accepted")) is bool
                       and local.get("outcome") in {"executed", "op-success", "policy-rejected", "invalid-script"})
        expected_match = has_verdict and local["accepted"] == expected
        core_match = has_verdict and local["accepted"] == core if compare_to_core else None
        results[name] = {
            "has_verdict": has_verdict,
            "matches_expected": expected_match,
            "matches_core": core_match,
            "status": ("no-verdict" if not has_verdict else
                       "mismatch" if not expected_match or core_match is False else
                       "matched" if compare_to_core else "outside-local-commitment-scope"),
        }
    return {"profiles": results,
            "matches_expected": all(row["matches_expected"] and row["matches_core"] is not False
                                    for row in results.values())}


def interpreter_provenance(fixtures: dict, metadata: dict) -> dict:
    """Match fixture claims to the single interpreter in Cargo's resolved graph."""
    packages = [package for package in metadata["packages"] if package["name"] == "bitcoin-scriptexec"]
    if len(packages) != 1:
        raise RuntimeError("Expected exactly one resolved bitcoin-scriptexec package")
    commit = fixtures["local_interpreter"]["commit"]
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError("Interpreter fixture pin must be an immutable commit")
    expected_source = f"git+https://github.com/adrienlacombe/rust-bitcoin-scriptexec?rev={commit}#{commit}"
    package = packages[0]
    if package.get("source") != expected_source:
        raise RuntimeError("Resolved interpreter source differs from the fixture's immutable fork pin")
    return {key: package[key] for key in ("name", "version", "source")}


class Node:
    def __init__(self, binary: Path, datadir: Path):
        self.datadir = datadir
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.options = ["-regtest", "-server", "-disablewallet", "-listen=0", "-connect=0",
                        "-dnsseed=0", "-discover=0", "-networkactive=0", "-acceptnonstdtxn=0",
                        "-persistmempool=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                        "-printtoconsole=0", "-dbcache=64", f"-mocktime={START_TIME}"]
        self.log = (datadir / "process.log").open("w")
        self.process = subprocess.Popen([str(binary), *self.options, f"-datadir={datadir}", f"-rpcport={self.port}"],
                                        stdout=self.log, stderr=subprocess.STDOUT)
        self.mocktime = START_TIME

    def rpc(self, method: str, *params):
        cookie = (self.datadir / "regtest/.cookie").read_bytes().strip()
        authorization = base64.b64encode(cookie).decode("ascii")
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/",
                                         data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                         headers={"Authorization": "Basic " + authorization, "Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result.get("error"):
            raise RPCError(result["error"])
        return result["result"]

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Core exited during startup: " + (self.datadir / "process.log").read_text())
            try:
                chain = self.rpc("getblockchaininfo")
                if chain["chain"] != "regtest" or chain["blocks"] != 0:
                    raise RuntimeError("Expected a fresh regtest chain")
                return
            except (FileNotFoundError, urllib.error.URLError, RPCError):
                time.sleep(0.1)
        raise RuntimeError("Core RPC startup timed out")

    def tick(self):
        self.mocktime += 600
        self.rpc("setmocktime", self.mocktime)

    def close(self):
        if self.process.poll() is None:
            try:
                self.rpc("stop")
            except (OSError, ValueError, RPCError):
                self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.log.close()


def consensus_check(node: Node, address: str, tx: dict) -> dict:
    """Use block validation with raw transactions, independently of mempool policy."""
    height = node.rpc("getblockcount")
    node.tick()
    try:
        result = node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        # Decode errors, missing inputs and infrastructure errors must never count
        # as an expected script rejection. All negative fixtures fail script checks.
        if error.code != -25 or not error.message.startswith("TestBlockValidity failed: block-script-verify-flag-failed ("):
            raise
        if node.rpc("getblockcount") != height:
            raise RuntimeError("Rejected fixture changed chain height")
        return {"accepted": False, "rpc_code": error.code, "reason": error.message}
    block = node.rpc("getblock", result["hash"])
    if block["height"] != height + 1 or tx["txid"] not in block["tx"]:
        raise RuntimeError("Core did not connect the fixture transaction")
    return {"accepted": True, "block_height": block["height"], "block_hash": result["hash"]}


def run(node: Node, fixtures: dict, report: dict):
    address = fixtures["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    hashes = []
    for _ in range(101):
        node.tick()
        hashes.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"] if output["scriptPubKey"]["hex"] == mining_script.hex())
    count = len(fixtures["fixtures"])
    outputs = [(FUNDING_VALUE, bytes.fromhex(row["script_pubkey_hex"])) for row in fixtures["fixtures"]]
    outputs.append((5_000_000_000 - count * FUNDING_VALUE - FEE, mining_script))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction id mismatch")
    node.tick()
    node.rpc("generatetoaddress", 1, address)
    report["funding_txid"] = funding["txid"]
    for index, fixture in enumerate(fixtures["fixtures"]):
        witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
        witness.extend([bytes.fromhex(fixture["script_hex"]), bytes.fromhex(fixture["control_block_hex"])])
        tx = transaction(funding["txid"], index, witness, [(FUNDING_VALUE - FEE, mining_script)])
        if tx["witness_bytes"] != fixture["metrics"]["taproot_witness_bytes"]:
            raise RuntimeError("Rust/Python witness serialization differs")
        decoded = node.rpc("decoderawtransaction", tx["hex"])
        for core_key, local_key in [("txid", "txid"), ("hash", "wtxid"), ("size", "total_bytes"),
                                    ("vsize", "vsize"), ("weight", "weight")]:
            if decoded[core_key] != tx[local_key]:
                raise RuntimeError(f"Core/Python transaction {core_key} differs for {fixture['name']}")
        policy = node.rpc("testmempoolaccept", [tx["hex"]])[0]
        if policy.get("txid") != tx["txid"] or policy.get("wtxid") != tx["wtxid"] or "allowed" not in policy:
            raise RuntimeError(f"Incomplete mempool result: {policy}")
        consensus = consensus_check(node, address, tx)
        local_comparison = compare_local_profiles(fixture, consensus, policy)
        matches = (consensus["accepted"] == fixture["expected"]["consensus"]
                   and policy["allowed"] == fixture["expected"]["policy"]
                   and rejection_matches(consensus, fixture["expected"]["consensus_rejection"])
                   and rejection_matches(policy, fixture["expected"]["policy_rejection"], policy=True)
                   and local_comparison["matches_expected"])
        # Keep report reviewable; the generator reproduces full witness bytecode.
        row = {key: value for key, value in fixture.items()
               if key not in {"script_hex", "data_witness_hex", "control_block_hex"}}
        row.update({"script_sha256": sha256(bytes.fromhex(fixture["script_hex"])),
                    "transaction": {key: value for key, value in tx.items() if key != "hex"},
                    "core": {"consensus": consensus, "policy": policy},
                    "local_profile_checks": local_comparison, "matches_expected": matches})
        row["evidence"] = "differentially-validated"
        row["deployment"] = ("policy-validated" if consensus["accepted"] and policy["allowed"]
                             else "consensus-validated" if consensus["accepted"] else "consensus-incompatible")
        report["results"].append(row)
        print(f"{'PASS' if matches else 'FAIL'} {fixture['name']}: consensus={consensus['accepted']} policy={policy['allowed']} profiles={local_comparison['matches_expected']} legacy={fixture['local']['outcome']}", file=sys.stderr)
    report["all_expectations_met"] = all(row["matches_expected"] for row in report["results"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true", help="allow first download of the hash-pinned release archive")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/core-validation.profiles.json")
    args = parser.parse_args()
    report = {"schema_version": 2, "all_expectations_met": False, "results": []}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        fixture_bytes = subprocess.check_output(["cargo", "run", "--locked", "--quiet", "--example", "core_validation_fixtures"], cwd=ROOT)
        fixtures = json.loads(fixture_bytes)
        if fixtures.get("schema_version") != 2:
            raise RuntimeError("Explicit local-profile fixture schema version 2 is required")
        if (fixtures["expected_bitcoin_core_version"] != RELEASE["version"]
                or fixtures["expected_bitcoin_core_commit"] != RELEASE["commit"]):
            raise RuntimeError("Fixture oracle pin differs from binary manifest")
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
        resolved_interpreter = interpreter_provenance(fixtures, metadata)
        report.update({"bitcoin_core": provenance, "fixture_sha256": sha256(fixture_bytes),
                       "fixture_count": fixtures["fixture_count"], "local_interpreter": fixtures["local_interpreter"],
                       "resolved_interpreter": resolved_interpreter,
                       "winternitz": fixtures["winternitz"], "initial_mocktime": START_TIME,
                       "consensus_method": "generateblock with raw transactions; verifies connected block contains txid",
                       "policy_method": "testmempoolaccept; -acceptnonstdtxn=0; remaining v30.3 default policy",
                       "scope": "These exact complete Taproot spends on regtest with active SegWit/Taproot rules. Supported local consensus/policy fragment verdicts must match Core, except the explicitly separate invalid-control-block commitment test. No mainnet broadcast, adversarial completeness, or general primitive deployment claim."})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-core-") as temporary:
            node = Node(binary, Path(temporary))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot")):
                    raise RuntimeError("Required regtest consensus deployments are inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot"]
                run(node, fixtures, report)
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
