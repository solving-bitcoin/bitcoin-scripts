"""Configuration evidence must not be promoted to unrelated measurements."""

import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import kb


RECORD = "signature/winternitz-constant-composition20"
CORE_CONFIG = "w20-composition-isolated-hash160-core-v30.3"
OLDER_CONFIG = "w20-composition-isolated-hash160"


class ConfigurationEvidenceTests(unittest.TestCase):
    def query(self, *args):
        return subprocess.check_output(
            [sys.executable, str(kb.ROOT / "tools/kb.py"), *args],
            cwd=kb.ROOT,
            text=True,
        )

    def best(self, *filters):
        return json.loads(self.query("best", RECORD, "script_bytes", *filters, "--json"))

    def test_policy_query_returns_only_the_validated_configuration(self):
        rows = self.best("--execution", "policy-validated")
        self.assertEqual([row["configuration"] for row in rows], [CORE_CONFIG])
        self.assertEqual(rows[0]["execution"], "policy-validated")
        self.assertEqual(rows[0]["evidence"], "differentially-validated")
        self.assertEqual(rows[0]["value"], 1599)

    def test_older_siblings_keep_the_record_defaults(self):
        rows = self.best("--execution", "research-unlimited")
        names = {row["configuration"] for row in rows}
        self.assertNotIn(CORE_CONFIG, names)
        self.assertIn(OLDER_CONFIG, names)
        self.assertTrue(all(row["execution"] == "research-unlimited" for row in rows))
        self.assertTrue(all(row["evidence"] == "locally-reproduced" for row in rows))

    def test_evidence_filter_composes_with_execution_filter(self):
        rows = self.best("--evidence", "differentially-validated")
        self.assertEqual([row["configuration"] for row in rows], [CORE_CONFIG])
        self.assertEqual(self.best("--evidence", "differentially-validated",
                                   "--execution", "research-unlimited"), [])

    def test_text_and_show_expose_the_configuration_qualifiers(self):
        text = self.query("best", RECORD, "script_bytes", "--execution", "policy-validated")
        self.assertIn(f"{RECORD}#{CORE_CONFIG}", text)
        self.assertIn("[differentially-validated / policy-validated]", text)
        shown = self.query("show", RECORD)
        self.assertIn("experimental / locally-reproduced / research-unlimited", shown)
        self.assertIn("evidence/execution: differentially-validated / policy-validated", shown)
        self.assertIn("evidence/execution: locally-reproduced / research-unlimited", shown)

    def test_list_keeps_its_record_level_filter(self):
        rows = json.loads(self.query("list", "--execution", "policy-validated", "--json"))
        self.assertNotIn(RECORD, {row["id"] for row in rows})
        rows = json.loads(self.query("list", "--execution", "research-unlimited", "--json"))
        self.assertIn(RECORD, {row["id"] for row in rows})

    def test_reproduction_parameters_do_not_override_classification(self):
        record = {"evidence": "locally-reproduced", "execution": "research-unlimited"}
        config = {"parameters": {"evidence": "differentially-validated", "execution_class": "policy-validated"}}
        self.assertEqual(kb.configuration_qualifiers(record, config),
                         ("locally-reproduced", "research-unlimited"))
        config["evidence"] = "inspected"
        self.assertEqual(kb.configuration_qualifiers(record, config),
                         ("inspected", "research-unlimited"))
        config["execution"] = "consensus-incompatible"
        self.assertEqual(kb.configuration_qualifiers(record, config),
                         ("inspected", "consensus-incompatible"))

    def test_validator_rejects_invalid_configuration_qualifiers(self):
        catalog = kb.load_catalog()
        for field, value in [("evidence", "verified"), ("execution", "deployable"),
                             ("evidence", None), ("execution", [])]:
            with self.subTest(field=field, value=value):
                modified = copy.deepcopy(catalog)
                record = next(row for row in modified["records"] if row["id"] == RECORD)
                config = next(row for row in record["configurations"] if row["id"] == CORE_CONFIG)
                config[field] = value
                with patch.object(kb, "load_catalog", return_value=modified):
                    errors = kb.validate()
                self.assertTrue(any(f"{RECORD}#{CORE_CONFIG}: invalid {field}" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
