#!/usr/bin/env python3
"""Explicit full-instance translation benchmark; uses up to 8.1 GB RAM.

This does not run other primitive tests or change their metrics. Tables are kept
in RAM, not written to disk. Opened-table audit is NOT public verification.
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
EXAMPLE = 'pointlock_subset_translation_probe'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example', EXAMPLE],
                   cwd=ROOT, check=True)
    binary = ROOT/'target/release/examples'/EXAMPLE
    source = ROOT/'examples'/f'{EXAMPLE}.rs'
    native = HERE/'anchored_publication_core_check.json'
    previous_hardware = json.loads((HERE/'anchored-setup-summary.json').read_text())['hardware']
    report = {
        'evidence': 'locally-reproduced', 'deployment': 'unclassified',
        'hardware': previous_hardware,
        'hardware_source': 'Existing same-host anchored-setup-summary.json; OS and CPU count checked below.',
        'current_os': platform.platform(), 'current_logical_cpus': os.cpu_count(),
        'source_sha256': digest(source), 'executable_sha256': digest(binary),
        'cargo_lock_sha256': digest(ROOT/'Cargo.lock'),
        'native_core_report_sha256': digest(native),
        'runs': {},
    }
    assert report['current_os'] == previous_hardware['os']
    assert report['current_logical_cpus'] == previous_hardware['logical_cpus']
    for name, extra, filename, expected in [
        ('row_mac', [], 'subset-translation-benchmark.json',
         '3253ab5d073c4c7e1b9ace60565d8f83dae1031d55a854619bff2f2bc2cea085'),
        ('label_hash', ['--label-hash-auth'], 'subset-translation-label-hash-benchmark.json',
         '8e50d450ec8fff25b7e81d3ff24efa13b585c8c636a5b37c41f4b0a77ae4ad2e'),
    ]:
        command = [str(binary), '--pools', '115', '--workers', '15', '--samples', '3',
                   '--native-recovery', str(native), *extra]
        data = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
        assert all(s['table_digest_blake3'] == expected for s in data['samples'])
        assert data['native_recovery_check']['payload_matches_core_report']
        assert data['native_recovery_report_sha256'] == digest(native)
        (HERE/filename).write_text(json.dumps(data, indent=2)+'\n')
        stats = {}
        for metric in ['preparation_ms', 'table_generation_ms', 'opened_table_audit_ms',
                       'generation_plus_opened_audit_ms', 'selected_opening_check_ms']:
            values = [s[metric] for s in data['samples']]
            stats[metric] = dict(first=values[0], median=statistics.median(values),
                                 min=min(values), max=max(values))
        report['runs'][name] = dict(command=command, summary=stats,
            bytes_identical_to_uncached_full_table=True,
            native_recovery_check=data['native_recovery_check'],
            table_bytes=data['table_bytes'], label_commitment_bytes=data['label_commitment_bytes'])
        print(name, json.dumps(stats), flush=True)
    report['scope'] = data['scope']
    (HERE/'subset-translation-summary.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
