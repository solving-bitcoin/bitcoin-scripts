#!/usr/bin/env python3
"""Deterministic host counterexamples for proposed public representation bridges.

No Bitcoin executor, network, transaction signing, or proof-of-work mining is
used. The raw hashlock predicate is explanatory, not a compiled primitive or
a Bitcoin Core consensus test. JSON records this boundary explicitly.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def public_identity_garbling():
    # All concatenation and XOR here are off-chain garbling operations. They
    # are not represented as existing Bitcoin Script operations.
    seed = b"bitcoin-lab/search4/public-garbling/2026-09-17"
    labels = {name: sha(seed + b"/" + name.encode())
              for name in ("input0", "input1", "output0", "output1")}
    rows = [xor(sha(b"identity-gate/" + labels[f"input{b}"]),
                labels[f"output{b}"]) for b in (0, 1)]

    def evaluate(b):
        return xor(sha(b"identity-gate/" + labels[f"input{b}"]), rows[b])

    # Exhaustive verification of the two-row table establishes that it really
    # computes identity on both possible inputs.
    assert all(evaluate(b) == labels[f"output{b}"] for b in (0, 1))
    cx0, cy1 = sha(labels["input0"]), sha(labels["output1"])

    # Predicate: SHA256 <cx0> EQUALVERIFY SHA256 <cy1> EQUAL.
    # The witness authenticates input 0 and supplies accepting output label 1.
    # Neither hashlock checks that the latter is the evaluation of the former.
    accept = (sha(labels["input0"]) == cx0
              and sha(labels["output1"]) == cy1)
    assert accept and evaluate(0) != labels["output1"]
    script = b"\xa8\x20" + cx0 + b"\x88\xa8\x20" + cy1 + b"\x87"
    assert len(script) == 70
    return {
        "seed_utf8": seed.decode(),
        "labels": {k: v.hex() for k, v in labels.items()},
        "rows": [row.hex() for row in rows],
        "setup_correct_for_both_inputs": True,
        "actual_input": 0,
        "correct_circuit_output": 0,
        "supplied_output_label": 1,
        "independent_hashlocks_accept": accept,
        "raw_explanatory_script_hex": script.hex(),
        "boundary": "complete-leaf: two label inputs, embedded commitments, and terminal predicate; no transaction context or native digest extraction",
        "raw_script_bytes_not_policy_compiled": len(script),
        "static_non_push_opcodes": 4,
        "initial_data_items": 2,
        "hint_items": 0,
        "main_plus_alt_stack_peak_by_inspection": 3,
        "witness_serialization": "not measured: no complete transaction or script type instantiated",
        "evidence": "locally-reproduced",
        "deployment": "unclassified",
    }


def exhaustive_index_relation():
    # Each transaction has two independent random-oracle gate arrays with
    # N=4 possible indices and p=1/2. Enumerate every possible array pair.
    # A fixed public permutation f restricts the index pair to (i,f(i)).
    n = 4
    arrays = list(itertools.product((0, 1), repeat=n))
    rows = []
    for f in itertools.permutations(range(n)):
        accepted = sum(any(a[i] and b[f[i]] for i in range(n))
                       for a in arrays for b in arrays)
        probability = Fraction(accepted, len(arrays) ** 2)
        assert probability == 1 - Fraction(3, 4) ** n
        rows.append({"permutation": list(f), "accepted": accepted,
                     "total_oracle_assignments": len(arrays) ** 2})
    return {
        "description": "Public permutation between two independent gate-index arrays; output labels of transactions do not enter the predicate",
        "N": n, "p": "1/2", "exact_success_probability": "175/256",
        "permutations_checked": len(rows), "rows": rows,
        "evidence": "locally-reproduced", "deployment": "unclassified",
    }


def cost_model():
    p = Fraction(780555, 2 ** 65)
    w = -math.log2(p)
    # First gate is evaluated for each candidate; second is evaluated only if
    # first passes. Success probability p^2 per paired candidate. This is an
    # unlimited independent-candidate model, excluding EC and setup costs.
    independent_pair_queries = (1 + p) / (p * p)
    return {
        "DER_gate_probability_exact": str(p),
        "W": w,
        "units": "ideal rare-predicate queries; EC operations, table construction, and funding setup excluded",
        "same_context_repeated_log2_queries": w,
        "independent_context_public_pair_relation_log2_queries": math.log2(independent_pair_queries),
        "applies_equally_to_allowed_and_disallowed_outputs": True,
        "evidence": "inspected", "deployment": "unclassified",
    }


def source_fingerprints():
    paths = [Path("/private/tmp/qsb-paper.tex"),
             Path("/private/tmp/colliderscript-2024-1802-research.pdf"),
             Path("/private/tmp/robinlinus-pages-migration/binohash.pdf")]
    return [{"path": str(path), "sha256": sha(path.read_bytes()).hex()}
            for path in paths if path.exists()]


def main():
    report = {
        "question": "Can public garbling or a fixed index relation turn a readable QSB digest into an exact-output covenant?",
        "scope": "Host counterexamples and exact toy enumeration only; no complete covenant or Script consensus validation",
        "public_garbling_counterexample": public_identity_garbling(),
        "fixed_index_relation": exhaustive_index_relation(),
        "rare_gate_cost_model": cost_model(),
        "source_fingerprints": source_fingerprints(),
    }
    destination = Path(__file__).with_suffix(".json")
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(destination),
                      "public_garbling_false_claim_accepted": True,
                      "permutations_checked": report["fixed_index_relation"]["permutations_checked"],
                      "pair_query_log2": report["rare_gate_cost_model"]["independent_context_public_pair_relation_log2_queries"]},
                     indent=2))


if __name__ == "__main__":
    main()
