#!/usr/bin/env python3
"""Validate CRC outputs and artifact bindings with the frozen bitwise oracle."""
import json
from pathlib import Path
import subprocess
import sys
from verify_probe import crc, num, sha, witness, compact

ROOT=Path(__file__).resolve().parents[2]


def artifact(a, outputs, expect_success, expect_error=None):
    assert a['stack_limit_enforced'] and a['charged_sig_budget']==0
    assert a['executed_opcodes'] is a['complete_validation_budget'] is None
    assert a['compilation_options']==('ALL' if a['raw_script_bytes']<=32768 else 'NONE')
    if a['compilation_options']=='NONE':
        assert a['script_bytes']==a['raw_script_bytes']
    assert len(a['script_sha256'])==len(a['tapleaf_hash'])==64
    assert a['error']==expect_error
    if expect_error is None:
        assert a['output_items']==len(outputs)
        assert a['output_sha256']==sha(witness([num(x) for x in outputs]))
        assert a['clean_success'] is expect_success
        assert a['local_policy']['error'] is None
        assert a['local_policy']['clean_success'] is expect_success


def main():
    path=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'research/crc8-nibble-feedback/metrics.json'
    r=json.loads(path.read_text());rev=r['source_revision']
    for p,digest in r['source_sha256'].items():
        assert sha((ROOT/p).read_bytes())==digest,p
        if rev!='0'*40:
            assert sha(subprocess.check_output(['git','show',f'{rev}:{p}'],cwd=ROOT))==digest,p
    meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=ROOT))
    for key,name in [('compiler_source','bitcoin-script'),('interpreter_source','bitcoin-scriptexec')]:
        packages=[p for p in meta['packages'] if p['name']==name]
        assert len(packages)==1 and packages[0]['source']==r[key]
    assert r['evidence']=='locally-reproduced' and r['execution']=='unclassified'
    assert r['polynomial']=='0x107' and r['initial_crc']==r['xorout']==0
    assert r['reflected_input'] is r['reflected_output'] is False
    assert len(r['rows'])==136 and len(r['compositions'])==24 and len(r['alias_contracts'])==4
    for row in r['rows']:
        d=[int(x,16) for x in row['input_nibbles_hex']];q=crc(d)
        assert len(d)==2*row['byte_count']==row['data_items']
        assert q==row['expected_crc'] and row['hint_items']==row['hint_bytes']==0 and row['all_data_at_entry']
        w=witness([num(x) for x in reversed(d)])
        assert len(w)==row['witness_bytes'] and sha(w)==row['witness_sha256']
        bound=(2 if row['canonical_input_required'] else 5)*len(d)+len(compact(len(d)))
        assert row['witness_domain_upper_bound']==bound
        assert row['witness_bytes_max']==(None if row['canonical_input_required'] else bound)
        artifact(row['fragment'],[q],q!=0)
        artifact(row['checked_leaf'],[1],True)
    for row in r['alias_contracts']:
        assert row['data_items']==18 and row['hint_items']==0
        w=witness([b'\x01\x00']*18)
        assert row['witness_bytes']==len(w) and row['witness_sha256']==sha(w)
        assert row['expected_crc']==crc([1]*18)
        a=row['checked_leaf']
        if row['canonical_input_required']:
            assert a['error']=='EqualVerify' and not a['clean_success']
        else:
            assert a['error'] is None and a['clean_success']
            assert a['output_sha256']==sha(witness([num(1)]))
        assert a['local_policy']['error']=='MinimalData'
    for row in r['compositions']:
        n=18*row['repeats'];d=[(7*i+3*g+3)%16 for g in range(row['repeats']) for i in range(18)]
        expected=[crc(d[g*18:(g+1)*18]) for g in range(row['repeats'])]
        assert expected==row['expected_top_first_crc'] and n==row['data_items']
        assert row['incremental_hint_items']==row['total_hint_items']==row['hint_bytes']==0 and row['all_data_at_entry']
        w=witness([num(x) for x in reversed(d)])
        assert len(w)==row['witness_bytes'] and sha(w)==row['witness_sha256']
        canonical=row['family'].endswith('-canonical')
        bound=(2 if canonical else 5)*n+len(compact(n))
        assert row['witness_domain_upper_bound']==bound
        assert row['witness_bytes_max']==(None if canonical else bound)
        assert row['fragment_component_policy_sum']+row['fragment_whole_policy_delta']==row['fragment']['script_bytes']
        if row['repeats']==46 and row['family'].startswith('feedback'):
            artifact(row['fragment'],[],False,'StackSize');artifact(row['checked_leaf'],[],False,'StackSize')
            assert row['checked_leaf']['max_combined_stack_items']==1001
        else:
            artifact(row['fragment'],list(reversed(expected)),False)
            artifact(row['checked_leaf'],[1],True)
            peak=n+(188 if row['family'].startswith('feedback') else 13)
            assert row['fragment']['max_combined_stack_items']==row['checked_leaf']['max_combined_stack_items']==peak
    print('Independent bitwise CRC-8: 136 scalar rows, four alias contracts, 24 compositions and source/Cargo/witness/compilation bindings pass; no Core/relay claim.')


if __name__=='__main__':
    main()
