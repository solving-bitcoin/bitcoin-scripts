#!/usr/bin/env python3
"""Focused complete 115-pool complement-translation + decoder benchmark.

Opened-table/garbling audit requires all secrets: NOT public setup checking.
No unrelated tests or metric regeneration; uses cached native scalar records.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLE = 'pointlock_complement_translation_probe'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example', EXAMPLE], cwd=ROOT, check=True)
    binary = ROOT/'target/release/examples'/EXAMPLE
    native = HERE/'direct_context_core_check.json'
    hardware = json.loads((HERE/'anchored-setup-summary.json').read_text())['hardware']
    assert platform.platform() == hardware['os']
    assert os.cpu_count() == hardware['logical_cpus']
    command = [str(binary), '--pools', '115', '--workers', '15', '--samples', '5', '--native-recovery', str(native)]
    result = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    assert result['native_recovery_check']['payload_matches']
    assert result['native_recovery_report_sha256'] == digest(native)
    assert len({s['table_digest_blake3'] for s in result['samples']}) == 1
    assert len({s['decoder_digest_blake3'] for s in result['samples']}) == 1
    metrics = ['preparation_ms', 'table_generation_ms', 'decoder_generation_ms', 'generation_ms', 'opened_audit_ms',
               'generation_plus_opened_audit_ms', 'selected_opening_check_ms']
    summary = {}
    for metric in metrics:
        values = [s[metric] for s in result['samples']]
        summary[metric] = dict(first=values[0], median=statistics.median(values), min=min(values), max=max(values))
    result['hardware'] = hardware
    result['hardware_source'] = 'Same-host anchored-setup-summary.json; current OS and logical CPU count checked.'
    result['command'] = command
    result['sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in [ROOT/'examples'/f'{EXAMPLE}.rs',
        ROOT/'examples/pointlock_membership_decoder.rs', Path(__file__), ROOT/'Cargo.lock', binary, native]}
    result['summary'] = summary
    (HERE/'complement-translation-benchmark.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(summary=summary, native_recovery_check=result['native_recovery_check'],
        table_bytes=result['encrypted_share_bytes'], decoder=result['samples'][0]), indent=2))


if __name__ == '__main__':
    main()
