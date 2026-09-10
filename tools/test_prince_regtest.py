"""Offline guards for the checked PRINCEv2/Core experiment."""

import copy
import json
import unittest

from prince_regtest import (EXPERIMENT, compare_local_profiles, rejection_matches,
                           resolved_provenance, run_passed, sha256,
                           validate_reference, validate_witness)


class PrinceHarnessTests(unittest.TestCase):
    @staticmethod
    def fixture():
        return {"expected": {"consensus": False, "policy": False,
                             "consensus_rejection": "verify", "policy_rejection": "minimaldata"},
                "local_profiles": {"consensus": {"outcome": "executed", "accepted": False, "error": "Verify"},
                                   "policy": {"outcome": "executed", "accepted": False, "error": "MinimalData"}}}

    def test_numeric_alias_rejections_preserve_profile_error_precedence(self):
        consensus = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Script failed an OP_VERIFY operation), input 0 of abc"}
        policy = {"allowed": False, "reject-reason": "mempool-script-verify-flag-failed (unknown error)"}
        self.assertTrue(rejection_matches(consensus, "verify"))
        self.assertFalse(rejection_matches(consensus, "equalverify"))
        self.assertTrue(rejection_matches(policy, "minimaldata", policy=True))
        self.assertFalse(rejection_matches(policy, "verify", policy=True))
        self.assertTrue(compare_local_profiles(self.fixture(), consensus, policy)["all_matched"])

    def test_panics_and_unexecuted_outcomes_never_count_as_rejection(self):
        for outcome in ["panic", "unsupported-opcode", "initialization-error", "op-success", "invalid-script", "policy-rejected"]:
            for accepted in [False, None]:
                fixture = self.fixture()
                fixture["local_profiles"]["consensus"].update(outcome=outcome, accepted=accepted)
                comparison = compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})
                with self.subTest(outcome=outcome, accepted=accepted):
                    self.assertFalse(comparison["all_matched"])
                    self.assertEqual(comparison["profiles"]["consensus"]["status"], "no-verdict")

    def test_wrong_error_or_core_boolean_cannot_pass(self):
        fixture = self.fixture()
        self.assertFalse(compare_local_profiles(fixture, {"accepted": True}, {"allowed": False})["all_matched"])
        fixture["local_profiles"]["policy"]["error"] = "Verify"
        self.assertFalse(compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})["all_matched"])
        fixture["expected"]["policy"] = True
        with self.assertRaises(RuntimeError):
            compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})

    def test_witness_accounting_includes_script_control_and_counts(self):
        fixture = {"data_witness_hex": [""]*16, "script_hex": "51", "control_block_hex": "c0",
                   "script_sha256": sha256(b"\x51"), "expected": {"consensus": True},
                   "metrics": {"data_items": 16, "taproot_witness_items": 18,
                               "data_witness_bytes": 17, "taproot_witness_bytes": 21,
                               "locking_script_bytes": 1, "hint_items": 0, "hint_bytes": 0}}
        complete = [b""]*16 + [b"\x51", b"\xc0"]
        validate_witness(fixture, complete)
        for key in fixture["metrics"]:
            mutated = copy.deepcopy(fixture)
            mutated["metrics"][key] += 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_witness(mutated, complete)
        with self.assertRaises(RuntimeError):
            validate_witness(fixture, complete[:-1])
        fixture["script_sha256"] = "00"*32
        with self.assertRaises(RuntimeError):
            validate_witness(fixture, complete)

    def test_c_reference_provenance_and_each_vector_are_bound(self):
        source = {"commit": "0c6172dcd85f1fe6a269519093a79c7350fe6e55", "source": "immutable-source",
                  "vectors": [{"key": "00", "plaintext": "11", "ciphertext": "22"}]}
        raw = json.dumps(source).encode()
        fixture = {"schema_version": 1, "experiment": EXPERIMENT, "fixture_count": 1,
                   "cipher_reference": {"commit": source["commit"], "source": source["source"], "fixture_sha256": sha256(raw)},
                   "fixtures": [{"name": "valid", "reference_vector_index": 0, "key_hex": "00",
                                 "reference_plaintext_hex": "11", "reference_ciphertext_hex": "22"}]}
        validate_reference(fixture, raw)
        for key in ["key_hex", "reference_plaintext_hex", "reference_ciphertext_hex"]:
            mutated = copy.deepcopy(fixture)
            mutated["fixtures"][0][key] = "ff"
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_reference(mutated, raw)
        with self.assertRaises(RuntimeError):
            validate_reference(fixture, raw+b"\n")

    def test_dependency_metadata_requires_one_matching_immutable_source(self):
        commit = "ab"*20
        fixtures = {field: {"name": name, "version": "0.0.0", "commit": commit,
                             "source": f"git+https://example.com/{name}?rev={commit}#{commit}"}
                    for field, name in [("local_interpreter", "bitcoin-scriptexec"), ("compiler", "bitcoin-script")]}
        metadata = {"packages": [{key: value for key, value in row.items() if key != "commit"}
                                  for row in fixtures.values()]}
        resolved_provenance(fixtures, metadata)
        for mutation in ["duplicate", "missing", "wrong-source", "wrong-version", "mutable-commit"]:
            claimed = copy.deepcopy(fixtures)
            graph = copy.deepcopy(metadata)
            if mutation == "duplicate":
                graph["packages"].append(graph["packages"][0])
            elif mutation == "missing":
                graph["packages"].pop()
            elif mutation == "wrong-source":
                graph["packages"][0]["source"] = None
            elif mutation == "wrong-version":
                graph["packages"][0]["version"] = "1.0.0"
            else:
                claimed["compiler"]["commit"] = "master"
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                resolved_provenance(claimed, graph)

    def test_partial_or_infrastructure_failed_reports_cannot_pass(self):
        report = {"results": [{}], "all_core_expectations_met": True,
                  "all_local_profile_comparisons_matched": True}
        self.assertTrue(run_passed(report))
        for update in [{"results": []}, {"all_core_expectations_met": False},
                       {"all_local_profile_comparisons_matched": False}, {"infrastructure_error": "RPC failed"}]:
            self.assertFalse(run_passed({**report, **update}))


if __name__ == "__main__":
    unittest.main()
