#!/usr/bin/env python3
"""Reproduce scoped full-instance setup timings and byte-identical parallel output."""
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example',
                    'pointlock_anchored_publication_probe'], cwd=ROOT, check=True)
    executable = ROOT/'target/release/examples/pointlock_anchored_publication_probe'
    try:
        cpu = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True,
                                      stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        # Previously measured on this host through read-only sysctl. A new host
        # must override this fallback in its report; do not guess its CPU model.
        cpu = 'unavailable through sandbox sysctl; see earlier measured hardware report'
    previous = json.loads((HERE/'anchored-setup-summary.json').read_text()) if (HERE/'anchored-setup-summary.json').exists() else {}
    report = dict(evidence='locally-reproduced', deployment='unclassified',
                  hardware=dict(cpu=cpu, logical_cpus=os.cpu_count(), os=platform.platform()),
                  source_sha256=hashlib.sha256((ROOT/'examples/pointlock_anchored_publication_probe.rs').read_bytes()).hexdigest(),
                  executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    if cpu.startswith('unavailable'):
        report['previous_measured_hardware'] = previous.get('hardware', {})
    for name, workers, samples, filename in [('serial', 1, 5, 'anchored-setup-benchmark.json'),
                                           ('parallel', 15, 10, 'anchored-setup-parallel-benchmark.json')]:
        command = [str(executable), '--benchmark', str(samples), '--workers', str(workers)]
        data = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
        (HERE/filename).write_text(json.dumps(data, indent=2)+'\n')
        report['scope'] = data['scope']
        stats = dict(workers=workers, samples=samples, command=command, summary={})
        for metric in ('generation_ms', 'verification_ms', 'combined_ms'):
            values = [row[metric] for row in data['samples']]
            stats['summary'][metric] = dict(min=min(values), median=statistics.median(values), max=max(values), first=values[0])
        report[name] = stats
    core = json.loads((HERE/'anchored_publication_core_check.json').read_text())
    prior = json.loads((HERE/'anchored-publication-transactions.json').read_text())
    command = [str(executable), '--workers', '15', '--funding-txid', core['excluded_test_setup_grant']['txid'],
               '--funding-vout', '0', '--funding-amount', '100000000']
    built = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    for key in ('funding', 'spending', 'negative_cases', 'payload_hex'):
        assert built[key] == prior[key], key
    report['parallel_transaction_bytes_identical_to_core_validated_fixture'] = True
    report['parallel_fixture_generation_ms'] = built['setup_generation_ms']
    report['parallel_fixture_verification_ms'] = built['setup_verification_ms']
    report['opening_transaction_attempts'] = built['opening_transaction_attempts']
    (HERE/'anchored-setup-summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
