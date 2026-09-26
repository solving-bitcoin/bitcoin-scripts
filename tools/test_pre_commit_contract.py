"""Run the Git-hook integration contract from the normal Python test suite."""

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent


class PreCommitContractTests(unittest.TestCase):
    def test_hook_contract_in_temporary_git_repositories(self):
        result = subprocess.run(
            ["bash", str(ROOT / "tools/test_pre_commit.sh")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: 9 pre-commit contract scenarios", result.stdout)


if __name__ == "__main__":
    unittest.main()
