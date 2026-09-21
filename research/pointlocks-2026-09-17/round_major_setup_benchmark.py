#!/usr/bin/env python3
"""Scoped 95-pool setup benchmark; excludes garbling and proof verification.

This measures generation and public checking of the point-lock instance,
not the complete setup required by the active goal. Fixed public test seeds.
"""
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLE = 'pointlock_round_major_publication_probe'


def summary(values):
    return dict(min=min(values), median=statistics.median(values), max=max(values), first=values[0])


def main():
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example', EXAMPLE], cwd=ROOT, check=True)
    binary = ROOT/'target/release/examples'/EXAMPLE
    def sysctl(name):
        return subprocess.check_output(['sysctl', '-n', name], text=True).strip()
    report = dict(scope=__doc__, evidence='locally-reproduced', deployment='unclassified',
        complete_goal_setup_measured=False,
        hardware=dict(cpu=sysctl('machdep.cpu.brand_string'), logical_cpus=int(sysctl('hw.logicalcpu')),
            memory_bytes=int(sysctl('hw.memsize')), os=platform.platform(),
            macos_version=subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip(),
            macos_build=subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip()),
        rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
        build_profile='release', executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, workers, samples in [('serial', 1, 3), ('parallel', 15, 7)]:
        command = [str(binary), '--benchmark', str(samples), '--workers', str(workers)]
        data = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
        assert data['pools'] == 95 and data['candidates'] == 5130
        report[name] = dict(command=command, workers=workers, samples=samples,
            raw=data, summary={key:summary([row[key] for row in data['samples']])
                              for key in ('generation_ms', 'verification_ms', 'combined_ms')})
    core = json.loads((HERE/'round_major_publication_core_check.json').read_text())
    prior = json.loads((HERE/'round-major-publication-transactions.json').read_text())
    # Repeat with a serial generator against precisely the same funding grant.
    # Only benchmark/timing counters may differ; all public and transaction bytes
    # must match the parallel native fixture, including every negative case.
    command = [str(binary), '--workers', '1', '--funding-txid', core['excluded_test_setup_grant']['txid'],
        '--funding-vout', '0', '--funding-amount', '100000000']
    built = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    for key in ('funding', 'spending', 'negative_cases', 'payload_hex', 'pools'):
        assert built[key] == prior[key], key
    report['serial_matches_core_validated_parallel_transaction_and_pool_bytes'] = True
    report['opening_transaction_attempts'] = built['opening_transaction_attempts']
    report['byte_identity_command'] = command
    paths = [Path(__file__), ROOT/f'examples/{EXAMPLE}.rs', ROOT/'Cargo.lock',
        HERE/'round_major_publication_core_check.py', HERE/'round_major_publication_core_check.json',
        HERE/'round-major-publication-transactions.json']
    report['source_and_artifact_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    path = HERE/'round-major-setup-summary.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(hardware=report['hardware'], serial=report['serial']['summary'],
        parallel=report['parallel']['summary'], serial_parallel_bytes_identical=True), indent=2))


if __name__ == '__main__':
    main()
