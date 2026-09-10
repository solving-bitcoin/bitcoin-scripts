"""Offline guards for the funded signature/Core experiment."""

import copy
import unittest

from tapscript_signature_regtest import (compare_local, rejection_matches,
                                        run_passed, validate_funded_manifest, validate_witness_counts)


class SignatureHarnessTests(unittest.TestCase):
    def test_panics_and_initialization_errors_are_not_consensus_rejections(self):
        for outcome in ["panic", "initialization-error", "unsupported"]:
            for accepted in [None, False]:
                fixture = {"local": {"outcome": outcome, "accepted": accepted, "error": "SchnorrSig"},
                           "expected": {"consensus_rejection": "schnorr-signature"}}
                comparison = compare_local(fixture, {"accepted": False})
                self.assertFalse(comparison["matches_consensus"])
                self.assertEqual(comparison["status"], "no-verdict")

    def test_wrong_local_error_cannot_satisfy_hash_type_precedence(self):
        fixture = {"local": {"outcome": "executed", "accepted": False, "error": "SchnorrSig"},
                   "expected": {"consensus_rejection": "schnorr-hashtype"}}
        self.assertFalse(compare_local(fixture, {"accepted": False})["matches_consensus"])
        fixture["local"]["error"] = "SchnorrSigHashtype"
        self.assertTrue(compare_local(fixture, {"accepted": False})["matches_consensus"])
        fixture["local"]["accepted"] = None
        self.assertFalse(compare_local(fixture, {"accepted": False})["matches_consensus"])

    def test_wrong_local_boolean_is_a_mismatch_even_without_error(self):
        fixture = {"local": {"outcome": "executed", "accepted": True, "error": None},
                   "expected": {"consensus_rejection": None}}
        self.assertTrue(compare_local(fixture, {"accepted": True})["matches_consensus"])
        self.assertFalse(compare_local(fixture, {"accepted": False})["matches_consensus"])

    def test_baseline_mode_never_waives_core_or_infrastructure_failures(self):
        report = {"all_core_expectations_met": True, "all_local_consensus_comparisons_matched": False}
        self.assertFalse(run_passed(report, False))
        self.assertTrue(run_passed(report, True))
        self.assertFalse(run_passed({**report, "all_core_expectations_met": False}, True))
        self.assertFalse(run_passed({**report, "infrastructure_error": "RPC failed"}, True))

    def test_unknown_key_policy_is_distinct_from_empty_checksigverify_consensus(self):
        policy = {"allowed": False, "reject-reason": "mempool-script-verify-flag-failed (Public key version reserved for soft-fork upgrades)"}
        consensus = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Script failed an OP_CHECKSIGVERIFY operation), input 0 of abc"}
        self.assertTrue(rejection_matches(policy, "discourage-upgradeable-pubkey", policy=True))
        self.assertFalse(rejection_matches(policy, "checksigverify", policy=True))
        self.assertTrue(rejection_matches(consensus, "checksigverify"))
        self.assertFalse(rejection_matches(consensus, "discourage-upgradeable-pubkey"))

    def test_funded_manifest_must_preserve_commitment_and_pin(self):
        manifest = {"fixture_count": 1, "funding_txid": None, "local_interpreter": {"commit": "abc"},
                    "fixtures": [{"name": "one", "script_hex": "51", "control_block_hex": "c0", "expected": {"consensus": True}}]}
        funded = copy.deepcopy(manifest)
        funded["funding_txid"] = "42"
        funded["fixtures"][0]["transaction"] = {"hex": "00"}
        validate_funded_manifest(manifest, funded, "42")
        for path, value in [(('funding_txid',), "other"), (('local_interpreter', 'commit'), "def"),
                            (('fixtures', 0, 'script_hex'), "00"), (('fixtures', 0, 'expected', 'consensus'), False)]:
            mutated = copy.deepcopy(funded)
            current = mutated
            for key in path[:-1]:
                current = current[key]
            current[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                validate_funded_manifest(manifest, mutated, "42")

    def test_complete_witness_count_includes_script_and_control_block(self):
        fixture = {"data_witness_hex": ["", "42"], "hint_items": 0,
                   "metrics": {"data_items": 2, "taproot_witness_items": 4, "hint_items": 0}}
        witness = [b"", b"\x42", b"\x51", b"\xc0"]
        validate_witness_counts(fixture, witness)
        for key, value in [("data_items", 1), ("taproot_witness_items", 2), ("hint_items", 1)]:
            mutated = copy.deepcopy(fixture)
            mutated["metrics"][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_witness_counts(mutated, witness)
        with self.assertRaises(RuntimeError):
            validate_witness_counts(fixture, witness[:-1])


if __name__ == "__main__":
    unittest.main()
