#!/usr/bin/env python3
"""Measure the composed honest scalar-label/message decoder, not public setup verification."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, default=15)
    parser.add_argument('--samples', type=int, default=5)
    args = parser.parse_args()
    subprocess.run(['cargo', 'build', '--release', '--locked', '--example',
                    'pointlock_total_message_probe'], cwd=ROOT, check=True)
    native = HERE/'anchored_publication_core_check.json'
    binary = ROOT/'target/release/examples/pointlock_total_message_probe'
    command = [str(binary), '--workers', str(args.workers), '--samples', str(args.samples),
               '--native-recovery', str(native)]
    report = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    report['command'] = command
    report['hardware'] = dict(cpu=output('sysctl', '-n', 'machdep.cpu.brand_string'),
        logical_cpus=int(output('sysctl', '-n', 'hw.logicalcpu')),
        memory_bytes=int(output('sysctl', '-n', 'hw.memsize')),
        machine=platform.machine(), operating_system=platform.system(),
        operating_system_version=output('sw_vers', '-productVersion'))
    paths = [ROOT/'examples/pointlock_total_message_probe.rs',
             ROOT/'examples/pointlock_complement_translation_probe.rs',
             ROOT/'examples/pointlock_membership_decoder.rs',
             ROOT/'examples/pointlock_decoders/mixed_radix.rs',
             ROOT/'examples/pointlock_decoders/composed.rs',
             Path(__file__), ROOT/'Cargo.lock', native, binary]
    report['sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    times = [key for key in report['samples'][0] if key.endswith('_ms')]
    report['summary'] = {key: dict(median=statistics.median(row[key] for row in report['samples']),
        minimum=min(row[key] for row in report['samples']), maximum=max(row[key] for row in report['samples']))
        for key in times}
    # Existing standalone paths acquire only child-module declarations. Their
    # historical benchmark remains historical; do not silently refresh it.
    historical = json.loads((HERE/'complement-translation-benchmark.json').read_text())
    declarations = {
        'examples/pointlock_complement_translation_probe.rs': '#[path = "pointlock_decoders/composed.rs"]\npub(crate) mod composed;\n',
        'examples/pointlock_membership_decoder.rs': '#[path = "pointlock_decoders/mixed_radix.rs"]\npub(crate) mod mixed_radix;\n',
    }
    report['historical_implementation_bodies_preserved'] = {}
    for path, declaration in declarations.items():
        body = (ROOT/path).read_text().replace(declaration, '', 1)
        # The later 5-of-54 profile raises only this guard; the old algorithm
        # and its n=50 behavior remain unchanged. Keep that exception explicit.
        if path == 'examples/pointlock_membership_decoder.rs':
            body = body.replace('n <= 54', 'n <= 50', 1)
        same = hashlib.sha256(body.encode()).hexdigest() == historical['sha256'][path]
        assert same, path
        report['historical_implementation_bodies_preserved'][path] = same
    report['historical_body_comparison_exceptions'] = ['membership decoder maximum n increased from 50 to 54']
    assert report['native_composition']['payload_matches']
    assert report['public_setup_verification_ms'] is None
    out = HERE/'total-message-decoder-benchmark.json'
    out.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(hardware=report['hardware'], summary=report['summary']), indent=2))


if __name__ == '__main__':
    main()
