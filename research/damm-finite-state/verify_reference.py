#!/usr/bin/env python3
"""Check the prototype table/report against exact preserved upstream source."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'research/damm-finite-state/initial-probe.json'
report = json.loads(report_path.read_text())
ref = root / 'research/damm-finite-state/reference/DammQuasigroupTable.cs'
body = re.search(r'_quasigroupTable\s*=\s*\[(.*?)\];', ref.read_text(), re.S).group(1)
flat = [int(n) for n in re.findall(r'\d+', body)]
assert len(flat) == 100
q = [flat[i:i+10] for i in range(0,100,10)]
source = (root / 'examples/damm_finite_state_probe.rs').read_text()
actual = ast.literal_eval(re.search(r'const Q:.*?=\s*(\[.*?\]);', source, re.S).group(1))
assert actual == q
assert hashlib.sha256(ref.read_bytes()).hexdigest() == 'b5be157bdbc16daf91a1caf75911cc648ac108488a878909a8b1e22cd75ceaf2'
assert all(sorted(row) == list(range(10)) for row in q)
assert all(sorted(q[r][c] for r in range(10)) == list(range(10)) for c in range(10))
assert all(q[x][x] == 0 for x in range(10))
assert all((q[q[c][x]][y] == q[q[c][y]][x]) == (x == y)
           for c in range(10) for x in range(10) for y in range(10))
for path, sha in report['source_sha256'].items():
    assert hashlib.sha256((root / path).read_bytes()).hexdigest() == sha, path
revision = report['source_revision']
if revision != '0' * 40:
    assert re.fullmatch(r'[a-f0-9]{40}', revision)
    for path, sha in report['source_sha256'].items():
        b = subprocess.check_output(['git', 'show', f'{revision}:{path}'], cwd=root)
        assert hashlib.sha256(b).hexdigest() == sha, (revision,path)
for row in report['rows']:
    n = row['n']
    digits = [(7*i+3)%10 for i in range(n)]
    state = 0
    for d in digits:
        state = q[state][d]
    assert row['expected_output'] == state
    assert row['data_items'] == n and row['hint_items'] == 0
    assert row['witness_bytes'] == (1 if n < 253 else 3) + sum(1 + (d != 0) for d in digits)
    for prefix in ['fragment','leaf']:
        assert row[f'{prefix}_options'] == ('ALL' if row[f'{prefix}_raw_bytes'] <= 32768 else 'NONE')
    if row['error'] is None:
        assert row['success'] and row['max_stack_items'] <= 1000
    else:
        assert row['error'] == 'StackSize' and not row['success']
        assert row['max_stack_items'] == 1001
print(f"Pinned upstream table/properties and {len(report['rows'])} report configurations match; no C# execution or Core differential claimed.")
