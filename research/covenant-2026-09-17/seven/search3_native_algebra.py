#!/usr/bin/env python3
"""Public secp256k1 equations and signed-graph rank checks, not a covenant.

No transaction, wallet, Script executor, secret erasure, or search is used.
OpenSSL independently verifies the four-root ECDSA fixtures.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legacy_same_signature_counterexample import (  # noqa: E402
    G, N, P, add, mul, signature_integer, verify,
)


def hscalar(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % N


def point_json(point):
    return None if point is None else [f"{coordinate:064x}" for coordinate in point]


def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def lift(x):
    if not 0 <= x < P:
        return None
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x**3 + 7) % P:
        return None
    return x, min(y, P - y)


def nonce_roots(r):
    roots = []
    for x in (r, r + N):
        root = lift(x)
        if root is not None:
            roots.extend([root, (root[0], -root[1] % P)])
    return roots


def point_sum(points):
    total = None
    for point in points:
        total = add(total, point)
    return total


def rank(matrix):
    rows = [[entry % N for entry in row] for row in matrix]
    pivot_row = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(pivot_row, len(rows))
                      if rows[i][column]), None)
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = pow(rows[pivot_row][column], -1, N)
        rows[pivot_row] = [entry * inverse % N for entry in rows[pivot_row]]
        for i in range(len(rows)):
            if i != pivot_row:
                scale = rows[i][column]
                rows[i] = [(entry - scale * base) % N
                           for entry, base in zip(rows[i], rows[pivot_row])]
        pivot_row += 1
        if pivot_row == len(rows):
            break
    return pivot_row


EDGES = [(0, 1), (1, 2), (2, 3), (3, 0),
         (0, 4), (4, 5), (5, 6), (6, 0)]


def cycle_offset(signs, digests, r):
    product, offset = 1, 0
    inverse_r = pow(r, -1, N)
    for tau, (left, right) in zip(signs, digests):
        product *= tau
        offset = (tau * offset + (tau * left - right) * inverse_r) % N
    return product, offset


def signed_figure_eight():
    k = pow(2, -1, N)
    r = mul(k)[0] % N
    assert len(nonce_roots(r)) == 2
    counts = {}
    examples = {}
    scalar_keys = [hscalar(f"search3 vertex {i}") for i in range(7)]
    arbitrary_digests = [(hscalar(f"search3 arbitrary {i} L"),
                          hscalar(f"search3 arbitrary {i} R")) for i in range(8)]
    arbitrary_satisfiable = 0
    for signs in itertools.product((-1, 1), repeat=8):
        rows = []
        compatible = []
        for i, ((u, v), tau) in enumerate(zip(EDGES, signs)):
            row = [0] * 7
            row[u], row[v] = -tau, 1
            rows.append(row)
            left = hscalar(f"search3 constructed {i} L")
            right = (tau * left + r * (tau * scalar_keys[u] - scalar_keys[v])) % N
            compatible.append((left, right))
        t1, c1 = cycle_offset(signs[:4], compatible[:4], r)
        t2, c2 = cycle_offset(signs[4:], compatible[4:], r)
        assert c1 == (1 - t1) * scalar_keys[0] % N
        assert c2 == (1 - t2) * scalar_keys[0] % N
        expected_rank = 6 if (t1, t2) == (1, 1) else 7
        assert rank(rows) == expected_rank
        anchor = [1] + [0] * 6
        assert rank(rows + [anchor]) == 7
        label = f"{t1:+d},{t2:+d}"
        counts[label] = counts.get(label, 0) + 1
        rhs = [(tau * left - right) * pow(r, -1, N) % N
               for tau, (left, right) in zip(signs, arbitrary_digests)]
        arbitrary_satisfiable += rank([row + [value] for row, value in zip(rows, rhs)]) == expected_rank
        if label not in examples:
            checks = []
            for (u, v), tau, (left, right) in zip(EDGES, signs, compatible):
                s = (left + r * scalar_keys[u]) * pow(k, -1, N) % N
                s = min(s, N - s)
                a = verify(left, r, s, mul(scalar_keys[u]))
                b = verify(right, r, s, mul(scalar_keys[v]))
                assert a[0] and b[0]
                observed = 1 if a[1] == b[1] else -1
                assert observed == tau
                checks.append({"left_digest_scalar": f"{left:064x}",
                               "right_digest_scalar": f"{right:064x}",
                               "s": f"{s:064x}", "relative_sign": tau,
                               "left_valid": a[0], "right_valid": b[0]})
            examples[label] = {"signs": signs, "coefficient_rank": expected_rank,
                               "independent_scalar_conditions": 8 - expected_rank,
                               "anchored_conditions": 9 - 7,
                               "cycle_offsets": [f"{c1:064x}", f"{c2:064x}"],
                               "checks": checks}
    assert counts == {"+1,+1": 64, "+1,-1": 64, "-1,+1": 64, "-1,-1": 64}
    assert arbitrary_satisfiable == 0
    return {"vertices": 7, "edges": EDGES, "patterns_checked": 256,
            "cycle_sign_counts": counts,
            "r": f"{r:064x}", "public_nonce_scalar": f"{k:064x}",
            "public_key_scalars": [f"{value:064x}" for value in scalar_keys],
            "one_arbitrary_digest_tuple_satisfiable_patterns": arbitrary_satisfiable,
            "warning": "Constructed digests satisfy algebra by design; they are not Bitcoin sighashes.",
            "representative_equation_fixtures": examples}


def openssl_checks(z, der, keys):
    results = []
    with tempfile.TemporaryDirectory(prefix="search3-public-ecdsa-") as name:
        folder = Path(name)
        (folder / "sig.der").write_bytes(der)
        for index, key in enumerate(keys):
            spki = bytes.fromhex("3036301006072a8648ce3d020106052b8104000a032200") + key
            (folder / "key.der").write_bytes(spki)
            entry = {"key_index": index}
            for label, digest_scalar, expected in [("same_digest", z, True),
                                                    ("changed_digest", (z + 1) % N, False)]:
                (folder / "digest.bin").write_bytes(digest_scalar.to_bytes(32, "big"))
                process = subprocess.run([
                    "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                    "-inkey", str(folder / "key.der"), "-sigfile", str(folder / "sig.der"),
                    "-in", str(folder / "digest.bin"), "-pkeyopt", "digest:sha256",
                ], text=True, capture_output=True)
                assert process.returncode in (0, 1), process.stderr
                accepted = process.returncode == 0
                assert accepted == expected, (label, process.stdout, process.stderr)
                entry[label] = accepted
            results.append(entry)
    return results


def four_root_gate():
    r, s = 2, 1
    roots = nonce_roots(r)
    assert len(roots) == 4 and point_sum(roots) is None
    z = hscalar("search3 four-root native digest equality fixture")
    keys = [mul(pow(r, -1, N), add(mul(s, root), mul(-z))) for root in roots]
    encoded = [compressed(key) for key in keys]
    assert len(set(encoded)) == 4 and all(len(key) == 33 for key in encoded)
    observed = [verify(z, r, s, key) for key in keys]
    assert all(valid for valid, _ in observed)
    assert [point for _, point in observed] == roots
    assert all(not verify((z + 1) % N, r, s, key)[0] for key in keys)
    assert point_sum(keys) == mul(-4 * z * pow(r, -1, N))
    # Keys 0 and 2 are distinct, share a context/signature, and have different
    # nonce x coordinates. Distinctness alone therefore does not force -R.
    assert roots[0][0] != roots[2][0]
    assert roots[0] != roots[2] and roots[0] != (roots[2][0], -roots[2][1] % P)
    body = signature_integer(r) + signature_integer(s)
    der = b"\x30" + bytes([len(body)]) + body
    independent = openssl_checks(z, der, encoded)
    return {"evidence": "differentially-validated", "deployment_class": "unclassified",
            "scope": "Public ECDSA equations and OpenSSL, no Script or Bitcoin transaction execution.",
            "digest_scalar": f"{z:064x}", "r": r, "s": s,
            "der_signature": der.hex(), "all_signature": (der + b"\x01").hex(),
            "nonce_roots": [point_json(point) for point in roots],
            "public_keys": [key.hex() for key in encoded],
            "openssl_checks": independent,
            "two_key_opposite_nonce_counterexample_indices": [0, 2],
            "search_trials": 0,
            "known_secret_material": "None: roots are lifted public x coordinates; no discarded keys/nonces.",
            "native_condition": "Reusing all four distinct keys and this signature in another context forces z'=z mod n.",
            "constant_signature_version_entry_key_items": 4,
            "incremental_hint_items": 0,
            "script_and_witness_metrics": "Not measured: no compiled Script instance is claimed."}


def main():
    report = {
        "question": "Can signed ECDSA graphs or exhaustive recovery keys yield native digest relations without erasure?",
        "result": "Two cycles add constraints; four recovery keys force scalar digest equality. No output bridge.",
        "evidence": "locally-reproduced", "deployment_class": "unclassified",
        "openssl_version": subprocess.check_output(["/usr/bin/openssl", "version"], text=True).strip(),
        "four_root_gate": four_root_gate(),
        "signed_figure_eight": signed_figure_eight(),
        "all_expectations_met": True,
    }
    output = Path(__file__).with_suffix(".json")
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(output), "all_expectations_met": True,
                      "sign_patterns": 256, "openssl_cases": 8}, indent=2))


if __name__ == "__main__":
    main()
