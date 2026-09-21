#!/usr/bin/env python3
"""Measure the full 95-pool honest translator/decoder, with public audit absent."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
EXAMPLE='pointlock_round_major_message_probe'


def output(*args):
    return subprocess.check_output(args,cwd=ROOT,text=True).strip()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers',type=int,default=15)
    parser.add_argument('--samples',type=int,default=5)
    args=parser.parse_args()
    subprocess.run(['cargo','build','--release','--locked','--example',EXAMPLE],cwd=ROOT,check=True)
    native=HERE/'round_major_publication_core_check.json'
    manifest=HERE/'round-major-publication-transactions.json'
    binary=ROOT/f'target/release/examples/{EXAMPLE}'
    command=[str(binary),'--workers',str(args.workers),'--samples',str(args.samples),
             '--native-recovery',str(native),'--native-manifest',str(manifest)]
    report=json.loads(subprocess.check_output(command,cwd=ROOT,text=True))
    assert report['native_composition']['payload_matches']
    assert report['native_composition']['scalar_opening_occurrences']==475
    assert report['boundary_checks']['equal_message_aliases_have_identical_output_labels']
    assert report['public_setup_verification_ms'] is None
    assert not report['public_malicious_setup_binding']
    assert not report['bitcoin_execution_this_run']
    assert report['radix']==3_162_510
    fingerprints={r['mixed_radix_fingerprint_blake3'] for r in report['samples']}
    assert len(fingerprints)==1
    report['command']=command
    report['hardware']=dict(cpu=output('sysctl','-n','machdep.cpu.brand_string'),
        logical_cpus=int(output('sysctl','-n','hw.logicalcpu')),
        memory_bytes=int(output('sysctl','-n','hw.memsize')),machine=platform.machine(),
        operating_system=platform.system(),operating_system_version=output('sw_vers','-productVersion'),
        operating_system_build=output('sw_vers','-buildVersion'),rustc=output('rustc','--version'))
    paths=[ROOT/f'examples/{EXAMPLE}.rs',ROOT/'examples/pointlock_decoders/round_major_complement.rs',
        ROOT/'examples/pointlock_decoders/round_major_composed.rs',ROOT/'examples/pointlock_decoders/mixed_radix.rs',
        ROOT/'examples/pointlock_membership_decoder.rs',Path(__file__),ROOT/'Cargo.lock',native,manifest,binary]
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    times=[k for k in report['samples'][0] if k.endswith('_ms')]
    report['summary']={k:dict(median=statistics.median(r[k] for r in report['samples']),
        minimum=min(r[k] for r in report['samples']),maximum=max(r[k] for r in report['samples'])) for k in times}
    report['all_expectations_met']=True
    (HERE/'round-major-message-benchmark.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(hardware=report['hardware'],summary=report['summary']),indent=2))


if __name__=='__main__': main()
