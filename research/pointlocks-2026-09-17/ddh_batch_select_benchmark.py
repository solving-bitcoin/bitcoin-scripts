#!/usr/bin/env python3
"""Full-2048-bit offchain batching timings, explicitly not full point-lock setup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu', help='Explicit CPU observed separately if sysctl is sandboxed')
    parser.add_argument('--memory-bytes', type=int, help='Explicit RAM observed separately if sysctl is sandboxed')
    args = parser.parse_args()
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example',
                    'pointlock_ddh_batch_select_probe'], cwd=ROOT, check=True)
    binary = ROOT/'target/release/examples/pointlock_ddh_batch_select_probe'
    cpu = args.cpu or subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip()
    memory = args.memory_bytes or int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True))
    result = dict(evidence='locally-reproduced', deployment='unclassified',
                  scope='Offchain DDH batch-select for all 2048 bits. No native binding or public ciphertext/setup verification.',
                  hardware=dict(cpu=cpu, logical_cpus=os.cpu_count(), memory_bytes=memory,
                                os=platform.platform(), hardware_values_supplied_explicitly=bool(args.cpu or args.memory_bytes)),
                  provenance=dict(source_sha256=sha(ROOT/'examples/pointlock_ddh_batch_select_probe.rs'),
                                  runner_sha256=sha(Path(__file__)), executable_sha256=sha(binary),
                                  cargo_lock_sha256=sha(ROOT/'Cargo.lock'),
                                  test_decoder_sha256=sha(ROOT/'examples/pointlock_membership_decoder.rs')),
                  configurations=[])
    for width in [16, 32, 128, 256]:
        command = [str(binary), '--width', str(width), '--workers', '15', '--samples', '5']
        data = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
        assert data['provenance']['source_sha256'] == result['provenance']['source_sha256']
        assert data['provenance']['cargo_lock_sha256'] == result['provenance']['cargo_lock_sha256']
        data['command'] = command
        data['summary'] = {}
        for metric in data['samples'][0]:
            values = [s[metric] for s in data['samples']]
            data['summary'][metric] = dict(min=min(values), median=statistics.median(values),
                                           max=max(values), first=values[0])
        data['first_generation_plus_audit_and_context_ms'] = (
            data['context_initialization_ms'] + data['samples'][0]['generation_plus_all_secrets_audit_ms'])
        result['configurations'].append(data)
        print(json.dumps(dict(width=width, raw_opening_bytes=data['raw_opening_bytes'],
                              public_payload_bytes=data['public_payload_bytes'], summary=data['summary'])), flush=True)
    serial_command = [str(binary), '--width', '32', '--workers', '1', '--samples', '1']
    serial = json.loads(subprocess.check_output(serial_command, cwd=ROOT, text=True))
    parallel = next(c for c in result['configurations'] if c['block_width'] == 32)
    assert serial['public_fingerprint'] == parallel['public_fingerprint']
    result['serial_control'] = serial
    result['serial_parallel_public_bytes_fingerprint_equal'] = True
    (HERE/'ddh-batch-select-benchmark.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
