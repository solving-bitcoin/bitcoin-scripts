#!/usr/bin/env python3
"""One candidate: defer a literal table into a Taproot leaf/control block.

Public deterministic host equations plus optional isolated Core transactions.
No wallet, key deletion, optional helper input, or field-library test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from r11_lookup_reference import (P, N, G, add, mul, point, encoded, compact,
    lookup, recovery_row, execute, digest, tail)
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary
from core_regtest import Node, consensus_check, transaction

CORE_COMMIT = '49faec4f87f5cd19c88db01a82e5c68b087c8227'
NUMS_X = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0


def h(data): return hashlib.sha256(data).digest()
def tagged(tag, data):
    prefix = h(tag.encode())
    return h(prefix+prefix+data)
def b32(n): return n.to_bytes(32, 'big')
def neg(a): return a[0], -a[1] % P
def even(a): return a if a[1] % 2 == 0 else neg(a)
def leaf_hash(script): return tagged('TapLeaf', b'\xc0'+compact(len(script))+script)


def codesep_position(script):
    pc, position, last = 0, 0, 0xffffffff
    while pc < len(script):
        op = script[pc]; pc += 1
        if op <= 75: pc += op
        elif op == 0xab: last = position
        position += 1
    return last


def commitment(internal, script):
    internal = even(internal)
    leaf = leaf_hash(script)
    tweak = int.from_bytes(tagged('TapTweak', b32(internal[0])+leaf), 'big')
    assert tweak < N
    output = add(internal, mul(tweak))
    assert output is not None
    control = bytes([0xc0 | (output[1] & 1)])+b32(internal[0])
    return {'point': output, 'tweak': tweak, 'leaf': leaf,
            'script_pubkey': b'\x51\x20'+b32(output[0]), 'control': control}


def check_commitment(script, control, output_script):
    if len(control) != 33 or control[0] & 0xfe != 0xc0:
        return False
    internal = point(b'\x02'+control[1:])
    c = commitment(internal, script)
    return c['script_pubkey'] == output_script and c['control'] == control


def output_serialization(outputs):
    return b''.join(struct.pack('<Q', value)+compact(len(script))+script for value, script in outputs)


def tapsighash(txid, index, amount, previous_script, outputs, extension=None):
    """BIP341 DEFAULT, one input, final sequence, no annex, version2/locktime0."""
    outpoint = bytes.fromhex(txid)[::-1]+struct.pack('<I', index)
    msg = b'\x00'+struct.pack('<II', 2, 0)
    msg += h(outpoint)+h(struct.pack('<Q', amount))
    msg += h(compact(len(previous_script))+previous_script)+h(b'\xff'*4)
    msg += h(output_serialization(outputs))
    msg += bytes([2 if extension is not None else 0])+bytes(4)
    if extension is not None: msg += extension
    return tagged('TapSighash', b'\x00'+msg), b'\x00'+msg


def schnorr_sign(secret, message, nonce):
    public = mul(secret)
    if public[1] & 1: secret = N-secret; public = neg(public)
    r = mul(nonce)
    if r[1] & 1: nonce = N-nonce; r = neg(r)
    challenge = int.from_bytes(tagged('BIP0340/challenge', b32(r[0])+b32(public[0])+message), 'big') % N
    s = (nonce+challenge*secret) % N
    signature = b32(r[0])+b32(s)
    assert add(mul(s), mul(-challenge, public)) == r
    return signature


def fixture():
    source = json.loads((HERE/'r11_lookup_reference.json').read_text())
    alpha = bytes.fromhex(source['signature_32_bytes'])
    # Keep the R11 layout and native recovery construction; use standard
    # recipient scripts so policy checks reach the signature opcode rules.
    intended = [(400000, b'\x00\x14'+b'\x11'*20), (590000, b'\x00\x14'+b'\x22'*20)]
    alternative = [(990000, b'\x00\x14'+b'\x33'*20)]
    refs = [digest(b'\x42'*32, tail(2), intended, j) for j in range(2)]
    rows = [recovery_row(alpha, z) for z in refs]
    script = lookup(rows, standalone=True)
    for j in range(2):
        stack, alt, _ = execute(script,[alpha,bytes([j]) if j else b''],lambda suffix:digest(b'\x42'*32,suffix,intended,j))
        assert stack == [b'\x01'] and not alt
    nums = point(b'\x02'+b32(NUMS_X))
    c = commitment(nums, script)
    assert check_commitment(script, c['control'], c['script_pubkey'])
    # Consensus BIP342 unknown-pubkey rule; real stack operations, no claimed
    # Schnorr/ECDSA check in this host callback.
    def unknown_key(sig, key, suffix):
        assert len(key) == 33 and suffix == tail(2)
        return bool(sig)
    stack, alt, metrics = execute(script, [alpha, b''], mock_check=unknown_key)
    assert stack == [b'\x01'] and not alt
    altered_rows = [recovery_row(alpha, (refs[0]+i) % N) for i in (1,2)]
    changed_script = lookup(altered_rows, standalone=True)
    assert len(changed_script) == len(script) and tail(2) == script[-len(tail(2)):]
    assert not check_commitment(changed_script, c['control'], c['script_pubkey'])
    changed_c = commitment(nums, changed_script)
    assert changed_c['script_pubkey'] != c['script_pubkey']
    # Candidate tweak compensation: cancel using a tweak computed from old P,
    # then actually rehash the newly revealed internal point P'. Both possible
    # output parities are tested because the funding program is x-only.
    compensations = []
    for sign in (1,-1):
        target = c['point'] if sign == 1 else neg(c['point'])
        trial = add(target, mul(-changed_c['tweak']))
        assert add(trial, mul(changed_c['tweak'])) == target
        actual = commitment(trial, changed_script)
        assert actual['script_pubkey'] != c['script_pubkey']
        compensations.append({'target_parity_sign': sign, 'trial_internal_compressed': encoded(trial).hex(),
            'canonical_internal_compressed': encoded(even(trial)).hex(),
            'assumed_tweak': f"{changed_c['tweak']:064x}", 'actual_tweak': f"{actual['tweak']:064x}",
            'formal_cancellation_with_assumed_tweak': True, 'actual_output_script': actual['script_pubkey'].hex(),
            'matches_fixed_output': False})
    xonly_rows = [tuple([row[0]]+[key[1:] for key in row[1:]]) for row in rows]
    xonly_script = lookup(xonly_rows, standalone=True)
    known_internal_scalar = 7
    known_internal = mul(known_internal_scalar)
    if known_internal[1]&1: known_internal_scalar = N-known_internal_scalar
    known = commitment(known_internal, script)
    output_secret = (known_internal_scalar+known['tweak']) % N
    assert mul(output_secret) == known['point']
    synthetic_txid = '42'*32
    scriptpath = [alpha, b'', script, c['control']]
    serialized_spends = [transaction(synthetic_txid,0,scriptpath,o) for o in (intended,alternative)]
    keypaths = []
    for j, outputs in enumerate((intended,alternative)):
        message, preimage = tapsighash(synthetic_txid,0,1000000,known['script_pubkey'],outputs)
        signature = schnorr_sign(output_secret,message,11+j)
        keypaths.append({'transaction': transaction(synthetic_txid,0,[signature],outputs),
                         'sighash': message.hex(),'sighash_preimage': preimage.hex(), 'public_nonce': 11+j})
    # Full leaf remains in the native Schnorr message despite identical suffix.
    separator_position = codesep_position(script)
    assert separator_position == codesep_position(changed_script)
    ext0 = leaf_hash(script)+b'\x00'+struct.pack('<I',separator_position)
    ext1 = leaf_hash(changed_script)+b'\x00'+struct.pack('<I',separator_position)
    msg0, pre0 = tapsighash(synthetic_txid,0,1000000,c['script_pubkey'],intended,ext0)
    msg1, pre1 = tapsighash(synthetic_txid,0,1000000,c['script_pubkey'],intended,ext1)
    assert msg0 != msg1
    report = {'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Does putting the literal recovery table in a Taproot leaf permit delayed table commitment with mandatory ECDSA execution?',
        'source_commit': CORE_COMMIT, 'sources': [
            f'https://github.com/bitcoin/bitcoin/blob/{CORE_COMMIT}/src/script/interpreter.cpp#L322-L357',
            f'https://github.com/bitcoin/bitcoin/blob/{CORE_COMMIT}/src/script/interpreter.cpp#L1720-L1758',
            'https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki',
            'https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki'],
        'BIP_inspection_date':'2026-09-17',
        'legacy_reference_scalars':[f'{z:064x}' for z in refs],
        'intended_ordered_outputs':[(v,s.hex()) for v,s in intended],
        'alternative_ordered_outputs':[(v,s.hex()) for v,s in alternative],
        'table_bytes':script.hex(), 'table_bytes_length':len(script),
        'leaf_preimage':(b'\xc0'+compact(len(script))+script).hex(), 'leaf_hash':c['leaf'].hex(),
        'internal_nums_x':b32(NUMS_X).hex(),'output_key_x':b32(c['point'][0]).hex(),
        'tweak':f"{c['tweak']:064x}", 'script_pubkey':c['script_pubkey'].hex(),'control_block':c['control'].hex(),
        'control_block_bytes':33, 'leaf_version':192,'merkle_path_items':0,
        'actual_argument_items':2,'hint_items':0,'full_witness_items':4,
        'combined_script_stack_peak':metrics['combined_stack_peak'],
        'serialized_witness_bytes':serialized_spends[0]['witness_bytes'],
        'validation_budget_initial':50+serialized_spends[0]['witness_bytes'],
        'validation_budget_used':150,'unknown_pubkey_checks':3,
        'literal_table_tapscript_host_rule':{'final_true':True,'actual_signature_verification_calls':0},
        'same_scriptpath_witness_different_outputs':serialized_spends,
        'changed_leaf_rejected_by_original_control':True,'changed_leaf_hash':changed_c['leaf'].hex(),
        'same_internal_changed_leaf_output':changed_c['script_pubkey'].hex(),
        'compensation_trials':compensations,
        'native_schnorr_full_leaf_extension':{'old':ext0.hex(),'changed':ext1.hex(),
            'same_codesep_position':separator_position,'same_post_separator_suffix':True,
            'old_sighash':msg0.hex(),'changed_sighash':msg1.hex(),
            'scope':'Exact BIP342 message extension comparison using the parsed separator position. The R11 unknown-key execution does not request a sighash.'},
        'known_internal_keypath':{'public_internal_scalar':known_internal_scalar,
            'public_output_scalar':output_secret,'script_pubkey':known['script_pubkey'].hex(),
            'signatures_over_serialized_transactions':keypaths},
        'xonly_variant_script':xonly_script.hex(),
        'xonly_variant_expectation':'32-byte alpha is not a64/65-byte Schnorr signature; rejects.',
        'construction_found':False,'setup_under_2_64_established':False}
    data = {'script':script,'rows':rows,'alpha':alpha,'nums':nums,'commitment':c,
            'changed_script':changed_script,'xonly_script':xonly_script,'known':known,
            'output_secret':output_secret,'intended':intended,'alternative':alternative}
    return report,data


def core_check(report,data):
    # Separate executable copy and process directory: never rewrites a binary
    # being used by another concurrent research task.
    with tempfile.TemporaryDirectory(prefix='covenant-r13-core-') as tmp:
        tmp=Path(tmp); cache=tmp/'binary'; cache.mkdir()
        existing=Path('/private/tmp/covenant-core-30.3')
        for archive in existing.glob('bitcoin-30.3-*.tar.gz'):
            shutil.copyfile(archive,cache/archive.name)
        binary,provenance=isolated_core_binary(cache,False)
        chain=tmp/'chain'; chain.mkdir(); node=Node(binary,chain)
        try:
            node.ready()
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101): node.tick(); blocks+=node.rpc('generatetoaddress',1,address)
            cb=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(o for o in cb['vout'] if o['scriptPubKey']['hex']==mining.hex())
            c=data['commitment']; xc=commitment(data['nums'],data['xonly_script'])
            locks=[c['script_pubkey']]*3+[xc['script_pubkey']]+[data['known']['script_pubkey']]*2
            fund=transaction(cb['txid'],coin['n'],[b'\x51'],[(1000000,s) for s in locks]+[(4993990000,mining)])
            assert consensus_check(node,address,fund)['accepted']
            results=[]
            def test(name,index,witness,outputs,expected):
                tx=transaction(fund['txid'],index,witness,outputs)
                policy=node.rpc('testmempoolaccept',[tx['hex']])[0]
                consensus=consensus_check(node,address,tx)
                assert consensus['accepted']==expected,(name,consensus)
                result={'name':name,'transaction':tx,'witness_items':len(witness),
                    'witness_hex':[i.hex() for i in witness],'policy':policy,'consensus':consensus,
                    'evidence':'differentially-validated',
                    'deployment_class':('policy-validated' if policy['allowed'] else 'consensus-validated') if expected else 'consensus-incompatible'}
                results.append(result)
                print('PASS',name,'accepted=',expected,file=sys.stderr,flush=True)
                return result
            witness=[data['alpha'],b'',data['script'],c['control']]
            first=test('R11-33byte-keys-intended-outputs',0,witness,data['intended'],True)
            # Validate conflicting outputs on separate branches from the same
            # funded outpoint, rather than silently changing input index.
            node.rpc('invalidateblock',first['consensus']['block_hash'])
            assert node.rpc('getrawmempool') == []
            first['validation_block_invalidated_for_same_outpoint_comparison']=True
            test('R11-same-witness-other-outputs',0,witness,data['alternative'],True)
            test('changed-table-original-control',2,[data['alpha'],b'',data['changed_script'],c['control']],data['intended'],False)
            test('xonly-keys-reject-32byte-alpha',3,[data['alpha'],b'',data['xonly_script'],xc['control']],data['intended'],False)
            for index,out in ((4,data['intended']),(5,data['alternative'])):
                msg,_=tapsighash(fund['txid'],index,1000000,data['known']['script_pubkey'],out)
                sig=schnorr_sign(data['output_secret'],msg,index+31)
                test('known-internal-keypath-'+str(index),index,[sig],out,True)
            report['core']={'provenance':provenance,'funding':fund,'results':results,'all_expectations_met':True}
        finally: node.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',action='store_true')
    args=parser.parse_args()
    report,data=fixture()
    if args.core: core_check(report,data)
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
