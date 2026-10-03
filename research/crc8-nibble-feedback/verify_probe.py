#!/usr/bin/env python3
"""Independent bitwise CRC oracle; no Core/relay verdict."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def crc(digits, initial=0):
    state = initial
    for digit in digits:
        assert 0 <= digit < 16
        for bit in (3, 2, 1, 0):
            feedback = ((state >> 7) ^ (digit >> bit)) & 1
            state = (state << 1) & 255
            if feedback:
                state ^= 7
    return state


def sha(data):
    return hashlib.sha256(data).hexdigest()


def num(value):
    if value == 0:
        return b""
    raw = value.to_bytes((value.bit_length()+7)//8, "little")
    return raw + (b"\x00" if raw[-1] & 128 else b"")


def compact(value):
    assert 0 <= value <= 65535
    return bytes([value]) if value < 253 else b"\xfd"+value.to_bytes(2, "little")


def witness(items):
    return compact(len(items))+b"".join(compact(len(item))+item for item in items)


def check_artifact(artifact, expected, success=None):
    assert artifact["error"] is None
    assert artifact["output_items"] == 1
    assert artifact["output_sha256"] == sha(witness([num(expected)]))
    assert artifact["compilation_options"] == ("ALL" if artifact["raw_script_bytes"] <= 32768 else "NONE")
    if artifact["compilation_options"] == "NONE":
        assert artifact["script_bytes"] == artifact["raw_script_bytes"]
    assert artifact["stack_limit_enforced"]
    assert artifact["charged_sig_budget"] == 0
    assert artifact["executed_opcodes"] is None
    assert artifact["complete_validation_budget"] is None
    if success is not None:
        assert artifact["clean_success"] is success


def main():
    report = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "research/crc8-nibble-feedback/initial-probe.json"
    data = json.loads(report.read_text())
    revision = data["source_revision"]
    for path, digest in data["source_sha256"].items():
        assert sha((ROOT/path).read_bytes()) == digest, path
        if revision != "0"*40:
            pinned = subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=ROOT)
            assert sha(pinned) == digest, path
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    for key, name in [("compiler_source", "bitcoin-script"), ("interpreter_source", "bitcoin-scriptexec")]:
        packages = [p for p in meta["packages"] if p["name"] == name]
        assert len(packages) == 1
        assert packages[0]["source"] == data[key]
    assert data["classification"] == {"evidence": "locally-reproduced", "execution": "unclassified"}
    assert data["polynomial"] == "0x107" and data["initial_crc"] == data["xorout"] == 0
    assert data["reflected_input"] is data["reflected_output"] is False
    assert crc([n for byte in b"123456789" for n in (byte>>4, byte & 15)]) == data["check_123456789"] == 244
    regression = data["private_reference_regression"]
    assert regression["input_nibbles"] == [0] and regression["initial_crc"] == regression["expected_crc"] == 0
    check_artifact(regression["valid_fragment"], 0, False)
    bad = regression["original_bad_step_fragment"]
    assert bad["error"] is None and bad["output_items"] == 5
    assert bad["output_sha256"] == sha(witness([b""]*5))
    assert bad["stack_limit_enforced"] and not bad["clean_success"]
    transition = bytes(crc([d], state) for state in range(256) for d in range(16))
    messages = bytes(crc([(x>>12) & 15, (x>>8) & 15, (x>>4) & 15, x & 15]) for x in range(65536))
    assert len(data["exhaustive"]) == 2
    for result in data["exhaustive"]:
        assert result["transition_cases"] == 4096 and result["two_byte_cases"] == 65536
        assert result["transition_output_sha256"] == sha(transition)
        assert result["two_byte_output_sha256"] == sha(messages)
    assert len(data["rows"]) == 32
    for row in data["rows"]:
        digits = row["logical_nibbles"]
        expected = crc(digits, row["initial_crc"])
        assert expected == row["expected_crc"]
        encoded = witness([num(d) for d in reversed(digits)])
        assert len(digits) == row["nibble_count"] == row["data_items"]
        assert row["hint_items"] == row["hint_bytes"] == 0 and row["all_data_at_entry"]
        assert row["witness_bytes"] == len(encoded) and row["witness_sha256"] == sha(encoded)
        check_artifact(row["fragment"], expected, expected != 0)
        check_artifact(row["checked_leaf"], 1, True)
    for result in data["frontiers"]:
        n = result["max_nibbles"]
        digits = [(i*7+3) % 16 for i in range(n)]
        assert result["fixture_crc"] == crc(digits)
        assert result["data_items"] == n and result["hint_items"] == 0 and result["all_data_at_entry"]
        assert result["fixture_witness_bytes"] == len(witness([num(d) for d in reversed(digits)]))
        assert result["allowed_witness_bytes_max"] == 5*n+len(compact(n))
        check_artifact(result["accepted_leaf"], 1, True)
        assert result["accepted_leaf"]["max_combined_stack_items"] == 1000
        assert result["one_more_leaf"]["max_combined_stack_items"] == 1001
        assert result["one_more_leaf"]["error"] == "StackSize"
    print("Independent bitwise CRC-8: 2*4096 transitions, 2*65536 two-byte messages, 32 rows, exact stack frontiers and source/Cargo/witness bindings pass. No Core/relay claim.")


if __name__ == "__main__":
    main()
