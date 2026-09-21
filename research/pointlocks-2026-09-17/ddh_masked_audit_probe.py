#!/usr/bin/env python3
"""Fresh-mask boundaries for the local DDH batch-select publication candidate.

Group-action disclosures can expose alternative labels even when their scalar
is hidden. Unbound mask points instead make a fixed-challenge linear audit
forgeable. Public deterministic fixtures; no native Bitcoin or ZKP construction.
"""
import hashlib
import itertools
import json
from pathlib import Path
import unittest

from ddh_linear_leakage_probe import (
    N, G, add, sub, mul, scalar, setup, dot, open_labels, finish_recovery,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def point_hex(point):
    return "00" if point is None else (bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")).hex()


def public_linear_point(points, coefficients):
    assert len(points) == len(coefficients)
    value = None
    for point, coefficient in zip(points, coefficients):
        value = add(value, mul(coefficient, point))
    return value


def recover_from_action(public, bits, key, delivered, coefficients, row, action):
    """Receiver-only recovery from action=<a,K>*R_row, without scalar <a,K>."""
    a = [v % N for v in coefficients]
    assert len(a) == len(bits) + 1 and 0 <= row < len(bits)
    denominator = (a[row + 1] - a[0] * bits[row]) % N
    if denominator == 0:
        return None
    u = mul(key, public["rows"][row])
    v = action
    for j, bit in enumerate(bits):
        if j != row:
            u = sub(u, mul(bit, public["matrix"][row][j]))
            v = sub(v, mul(a[j + 1], public["matrix"][row][j]))
    diagonal = mul(pow(denominator, -1, N), sub(v, mul(a[0], u)))
    constant = sub(u, mul(bits[row], diagonal))
    zero = sub(public["offset"][row], constant)
    one = add(zero, sub(public["matrix"][row][row], diagonal))
    return finish_recovery(public, bits, delivered, row, zero, one)


def recover_from_masked_response(public, bits, key, delivered, coefficients,
                                 row, response, mask_point, mask_action):
    """Only public response h+<a,K>, hG, hR_i, and the valid opening are used."""
    expected = add(mask_point, public_linear_point(public["key_points"], coefficients))
    if mul(response) != expected:
        return None
    action = sub(mul(response, public["rows"][row]), mask_action)
    return recover_from_action(public, bits, key, delivered, coefficients, row, action)


def coefficient_cases():
    tested = violations = universally_safe = 0
    for row in range(3):
        for a in itertools.product(range(5), repeat=4):
            all_safe = True
            for bits in itertools.product((0, 1), repeat=3):
                redundant_at_row = all((a[j] - a[0] * (1, *bits)[j]) % 5 == 0
                                       for j in (0, row + 1))
                has_determinant = (a[row + 1] - a[0] * bits[row]) % 5 != 0
                assert redundant_at_row != has_determinant
                tested += 1
                violations += int(has_determinant)
                all_safe &= not has_determinant
            assert all_safe == (a[0] == 0 and a[row + 1] == 0)
            universally_safe += int(all_safe)
    return dict(field=5, messages=8, row_coefficient_message_cases=tested,
                nonzero_determinants=violations,
                universally_redundant_row_coefficient_cases=universally_safe)


def masked_curve_cases():
    public, keys, labels = setup(3)
    vectors = [[int(i == j) for i in range(4)] for j in range(4)]
    vectors += [[1, 3, 5, 7], [N - 1, 0, 2, N - 3]]
    recoveries, redundant, wrong_action_rejections = [], 0, 0
    for bits in itertools.product((0, 1), repeat=3):
        key = dot((1, *bits), keys)
        delivered = open_labels(public, bits, key)
        for number, a in enumerate(vectors):
            # Secret fixture generation is outside the receiver-only functions.
            h = scalar(f"masked-audit/pad/{bits}/{number}")
            response = (h + dot(a, keys)) % N
            mask_point = mul(h)
            for row in range(3):
                mask_action = mul(h, public["rows"][row])
                got = recover_from_masked_response(public, bits, key, delivered, a,
                                                   row, response, mask_point, mask_action)
                informative = (a[row + 1] - a[0] * bits[row]) % N != 0
                if informative:
                    assert got is not None
                    assert got["alternatives"] == [labels[i][1 - bits[i]].hex() for i in range(3)]
                    recoveries.append(dict(bits=list(bits), coefficient_case=number, row=row,
                                           alternatives=got["alternatives"]))
                    # A false group action must not be reported as a real opening.
                    assert recover_from_masked_response(public, bits, key, delivered, a, row,
                                                        response, mask_point, add(mask_action, G)) is None
                    wrong_action_rejections += 1
                else:
                    assert got is None
                    redundant += 1
    return dict(full_alternative_label_recoveries=recoveries, redundant_row_controls=redundant,
                wrong_action_rejections=wrong_action_rejections,
                receiver_inputs_exclude_mask_scalar_and_hidden_key_vector=True)


def statement_challenge(public, column):
    """Challenge fixed by the statement alone, before proof mask commitments.

    This deliberately is NOT Fiat-Shamir: a sound transform must bind the
    proof commitments as well. It models the proposed plain algebraic audit.
    """
    statement = dict(domain="bitcoin-lab/fixed-challenge-masked-audit/v1",
                     column=column, key=point_hex(public["key_points"][column + 1]),
                     rows=[point_hex(r) for r in public["rows"]],
                     claims={str(i): point_hex(public["matrix"][i][column])
                             for i in range(len(public["rows"])) if i != column})
    encoded = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    return int.from_bytes(hashlib.sha256(encoded).digest(), "big") % (N - 1) + 1


def verify_linear_certificate(public, column, certificate):
    c = statement_challenge(public, column)
    response = certificate["response"]
    rows = [i for i in range(len(public["rows"])) if i != column]
    if set(certificate["mask_actions"]) != set(rows):
        return False
    if mul(response) != add(certificate["mask_point"], mul(c, public["key_points"][column + 1])):
        return False
    return all(mul(response, public["rows"][i]) ==
               add(certificate["mask_actions"][i], mul(c, public["matrix"][i][column]))
               for i in rows)


def forge_linear_certificate(public, column):
    """No hidden key or mask scalar: choose commitments after the challenge."""
    c = statement_challenge(public, column)
    response = scalar("masked-audit/forged-public-response")
    return dict(response=response,
                mask_point=sub(mul(response), mul(c, public["key_points"][column + 1])),
                mask_actions={i: sub(mul(response, public["rows"][i]),
                                     mul(c, public["matrix"][i][column]))
                              for i in range(len(public["rows"])) if i != column})


def certificate_cases():
    public, keys, _ = setup(3)
    column, changed_row = 1, 0
    c = statement_challenge(public, column)
    h = scalar("masked-audit/honest-certificate-pad")
    honest = dict(response=(h + c * keys[column + 1]) % N, mask_point=mul(h),
                  mask_actions={i: mul(h, public["rows"][i])
                                for i in range(3) if i != column})
    assert verify_linear_certificate(public, column, honest)

    # Keep all key points, row bases, offsets and label hashes unchanged.
    public["matrix"][changed_row][column] = add(public["matrix"][changed_row][column], G)
    assert public["matrix"][changed_row][column] != mul(keys[column + 1], public["rows"][changed_row])
    forged = forge_linear_certificate(public, column)
    assert verify_linear_certificate(public, column, forged)
    # With fixture secrets, independently check the missing common-mask relation.
    fake_h = (forged["response"] - statement_challenge(public, column) * keys[column + 1]) % N
    assert forged["mask_point"] == mul(fake_h)
    assert forged["mask_actions"][changed_row] != mul(fake_h, public["rows"][changed_row])

    opening_rows = []
    for bits in itertools.product((0, 1), repeat=3):
        key = dot((1, *bits), keys)
        try:
            open_labels(public, bits, key)
            accepted_labels = True
        except AssertionError:
            accepted_labels = False
        assert accepted_labels == (bits[column] == 0)
        opening_rows.append(dict(bits=list(bits), original_label_checks_pass=accepted_labels))

    wrong_point = dict(forged, mask_point=add(forged["mask_point"], G))
    wrong_row = dict(forged, mask_actions=dict(forged["mask_actions"]))
    wrong_row["mask_actions"][changed_row] = add(wrong_row["mask_actions"][changed_row], G)
    wrong_response = dict(forged, response=(forged["response"] + 1) % N)
    for bad in (wrong_point, wrong_row, wrong_response):
        assert not verify_linear_certificate(public, column, bad)
    return dict(honest_certificate_passes=True, changed_off_diagonal_cell=[changed_row, column],
                forged_certificate_passes=True, common_mask_relation_is_false=True,
                forging_function_receives_public_data_only=True,
                challenge_binds_proof_commitments=False, proof_rejection_controls=3,
                opening_controls=opening_rows,
                forged_public_certificate=dict(response=f"{forged['response']:064x}",
                    mask_point=point_hex(forged["mask_point"]),
                    mask_actions={str(i): point_hex(p) for i, p in forged["mask_actions"].items()}))


class MaskedAuditTests(unittest.TestCase):
    def test_all_future_messages_allow_only_off_diagonal_setup_actions(self):
        self.assertEqual(coefficient_cases()["universally_redundant_row_coefficient_cases"], 75)

    def test_hiding_the_scalar_does_not_hide_its_revealed_row_action(self):
        rows = masked_curve_cases()
        self.assertEqual(len(rows["full_alternative_label_recoveries"]), 80)
        self.assertEqual(rows["redundant_row_controls"], 64)

    def test_unbound_mask_points_absorb_a_false_table_claim(self):
        result = certificate_cases()
        self.assertEqual(sum(not r["original_label_checks_pass"] for r in result["opening_controls"]), 4)


if __name__ == "__main__":
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    sources = [Path(__file__), HERE / "ddh_linear_leakage_probe.py", HERE / "core_check.py",
               HERE.parent / "covenant-2026-09-17/legacy_same_signature_counterexample.py",
               ROOT / "examples/pointlock_ddh_batch_select_probe.rs"]
    report = dict(scope=__doc__, evidence="locally-reproduced", deployment="unclassified",
                  tests_run=program.result.testsRun, coefficient_cases=coefficient_cases(),
                  masked_actions=masked_curve_cases(), linear_certificate=certificate_cases(),
                  native_execution=False, public_setup_verifier_supplied=False,
                  setup_benchmark=False, new_script_bytes=None, new_witness_bytes=None,
                  new_hint_items=None, new_stack_peak=None,
                  source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sources})
    (HERE / "ddh-masked-audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(tests_run=report["tests_run"], coefficient_cases=report["coefficient_cases"],
                         alternative_label_recoveries=len(report["masked_actions"]["full_alternative_label_recoveries"]),
                         redundant_rows=report["masked_actions"]["redundant_row_controls"],
                         fixed_challenge_forgery=report["linear_certificate"]["forged_certificate_passes"]), indent=2))
