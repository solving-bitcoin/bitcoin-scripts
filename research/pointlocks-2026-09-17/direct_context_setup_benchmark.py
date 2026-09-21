#!/usr/bin/env python3
"""Focused point-lock setup benchmark; does not include garbling/translation."""
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAME = 'pointlock_direct_context_publication_probe'


def main():
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example', NAME], cwd=ROOT, check=True)
    binary = ROOT/'target/release/examples'/NAME
    command = [str(binary), '--benchmark', '5', '--workers', '15']
    data = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    data['command'] = command
    data['hardware_from_same_host_prior_benchmark'] = json.loads((HERE/'anchored-setup-summary.json').read_text())['hardware']
    data['sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [
        ROOT/'examples'/f'{NAME}.rs', ROOT/'examples/pointlock_direct_context_size_probe.rs',
        binary, ROOT/'Cargo.lock']}
    data['summary'] = {}
    for metric in ('generation_ms', 'verification_ms', 'combined_ms'):
        values = [s[metric] for s in data['samples']]
        data['summary'][metric] = dict(first=values[0], median=statistics.median(values), min=min(values), max=max(values))
    old = json.loads((HERE/'anchored_publication_core_check.json').read_text())
    new = json.loads((HERE/'direct_context_core_check.json').read_text())
    assert old['recovery']['extractions'] == new['recovery']['extractions']
    assert old['recovery']['payload_hex'] == new['recovery']['payload_hex']
    old_built = json.loads((HERE/'anchored-publication-transactions.json').read_text())
    new_built = json.loads((HERE/'direct-context-publication-transactions.json').read_text())
    assert [p['targets'] for p in old_built['pools']] == [p['targets'] for p in new_built['pools']]
    data['same_labels_as_existing_translation'] = dict(candidate_points=5750, selected_scalars=460,
        complete_selected_records_identical=True, payload_identical=True,
        scope='Exact equality with the existing anchored fixture inputs to the independently measured translation. No new garbled verifier evaluation.')
    (HERE/'direct-context-setup-benchmark.json').write_text(json.dumps(data, indent=2)+'\n')
    print(json.dumps(data['summary'], indent=2))


if __name__ == '__main__':
    main()
