#!/usr/bin/env python3
"""Staged SegWit table publication versus mandatory descendant binding.

Host transaction bytes, BIP143 preimages, and actual public ECDSA equations.
No Core execution, witness-to-descendant oracle, or complete covenant claimed.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE))
from r11_lookup_reference import N, compact, push, recovery_row, execute, tail


def sha(x): return hashlib.sha256(x).digest()
def h256(x): return sha(sha(x))
def vec(x): return compact(len(x))+x
def p2wsh(script): return b'\x00\x20'+sha(script)
def p2sh(script): return b'\xa9\x14'+hashlib.new('ripemd160',sha(script)).digest()+b'\x87'
def outbytes(outputs): return b''.join(struct.pack('<Q',v)+vec(s) for v,s in outputs)


def tx(outpoint, outputs, *, script_sig=b'', witness=None, locktime=0):
    # A single mandatory input; outpoint is serialized hash || uint32 index.
    assert len(outpoint)==36
    prefix=struct.pack('<I',2)
    body=b'\x01'+outpoint+vec(script_sig)+b'\xff'*4+compact(len(outputs))+outbytes(outputs)
    end=struct.pack('<I',locktime)
    base=prefix+body+end
    wb=b'' if witness is None else compact(len(witness))+b''.join(vec(x) for x in witness)
    raw=base if witness is None else prefix+b'\x00\x01'+body+wb+end
    return {'base':base,'raw':raw,'txid_wire':h256(base),'wtxid_wire':h256(raw),
            'outpoint':outpoint,'outputs':outputs,'locktime':locktime,'witness_bytes':len(wb),
            'weight':4*len(base)+(len(raw)-len(base))}


def show(t):
    return {'base_hex':t['base'].hex(),'transaction_hex':t['raw'].hex(),
            'txid':t['txid_wire'][::-1].hex(),'wtxid':t['wtxid_wire'][::-1].hex(),
            'spent_outpoint_wire':t['outpoint'].hex(),'witness_bytes':t['witness_bytes'],
            'total_bytes':len(t['raw']),'weight':t['weight']}


def bip143(t, code, amount, flag=1):
    mode=flag&31
    prevouts=bytes(32) if flag&128 else h256(t['outpoint'])
    sequence=bytes(32) if flag&128 or mode in (2,3) else h256(b'\xff'*4)
    if mode not in (2,3): outputs=h256(outbytes(t['outputs']))
    elif mode==3 and t['outputs']: outputs=h256(outbytes(t['outputs'][:1]))
    else: outputs=bytes(32)
    preimage=struct.pack('<I',2)+prevouts+sequence+t['outpoint']+vec(code)
    preimage+=struct.pack('<Q',amount)+b'\xff'*4+outputs+struct.pack('<II',t['locktime'],flag)
    assert preimage[68:104]==t['outpoint']
    return int.from_bytes(h256(preimage),'big')%N,preimage


def descendant_script(alpha):
    # Literal alpha pin, four actual native operands, table-independent suffix.
    return bytes.fromhex('7454885379')+push(alpha)+bytes.fromhex('88ab')+tail(1)


def native_row(funding,outputs,alpha,code,amount=999000):
    t=tx(funding['txid_wire']+bytes(4),outputs)
    z,preimage=bip143(t,code,amount)
    row=recovery_row(alpha,z)
    script=descendant_script(alpha)
    stack,alt,metrics=execute(script,list(row),lambda suffix:bip143(t,suffix,amount)[0])
    assert stack==[b'\x01'] and not alt and len(metrics['native_checks'])==3
    t=tx(funding['txid_wire']+bytes(4),outputs,witness=[*row,script])
    return row,t,metrics,preimage


def chain(blob, nested, stages, final_script):
    # Give the proposed ancestor object a real hash commitment. This only
    # authenticates publication when F spends A; it does NOT grant a future
    # script access to that ancestor witness or its row interpretation.
    ancestor_script=b'\xa8'+push(sha(blob))+b'\x87'
    program=p2wsh(ancestor_script)
    ancestor_lock=p2sh(program) if nested else program
    a=tx(b'\x24'*32+bytes(4),[(1000000,ancestor_lock)])
    records=[show(a)]
    previous=a
    for step in range(stages):
        next_script=final_script if step==stages-1 else b'\x51'
        script_sig=push(program) if nested and step==0 else b''
        witness=[blob,ancestor_script] if step==0 else [b'\x51']
        previous=tx(previous['txid_wire']+bytes(4),[(999000,p2wsh(next_script))],script_sig=script_sig,witness=witness)
        records.append(show(previous))
    return previous,{'nested':nested,'stages':stages,'ancestor_object_sha256':sha(blob).hex(),
        'ancestor_witness_script':ancestor_script.hex(),'ancestor_lock':ancestor_lock.hex(),
        'first_stage_script_sig':(push(program) if nested else b'').hex(),
        'ancestor_blob_passes_hash_guard':sha(blob)==ancestor_script[2:34],
        'transactions':records}


def graph_for(stages):
    vertices=['rows','row_hash','ancestor_script','A.txid']+[f'F{i}.txid' for i in range(stages)]+['T.own_outpoint','T.native_digest']
    edges=list(zip(vertices,vertices[1:]))+[(vertices[-1],vertices[0])]
    # This explicit cycle is a computation-dependency graph, not a Bitcoin
    # transaction cycle. Every serialized transaction chain itself is acyclic.
    assert edges[-1][1]==vertices[0] and len(set(vertices))==len(vertices)
    return {'vertices':vertices,'edges':edges,'cycle':vertices+[vertices[0]]}


def main():
    r11=json.loads((HERE/'r11_lookup_reference.json').read_text())
    alpha=bytes.fromhex(r11['signature_32_bytes'])
    final=descendant_script(alpha)
    intended=[(400000,b'\x00\x14'+b'\x11'*20),(589000,b'\x00\x14'+b'\x22'*20)]
    changed=[(989000,b'\x00\x14'+b'\x33'*20)]
    # First test the apparent escape: publication as witness data under a
    # fixed ancestor program really is excluded from F's txid.
    publisher=b'\x75\x51'  # DROP TRUE; explicitly no row commitment
    a=tx(b'\x24'*32+bytes(4),[(1000000,p2wsh(publisher))])
    fbase=tx(a['txid_wire']+bytes(4),[(999000,p2wsh(final))])
    good,tgood,goodmetrics,goodpre=native_row(fbase,intended,alpha,tail(1))
    bad,tbad,badmetrics,badpre=native_row(fbase,changed,alpha,tail(1))
    goodblob,badblob=b''.join(good),b''.join(bad)
    assert len(goodblob)==len(badblob)==131 and goodblob!=badblob
    fgood=tx(a['txid_wire']+bytes(4),fbase['outputs'],witness=[goodblob,publisher])
    fbad=tx(a['txid_wire']+bytes(4),fbase['outputs'],witness=[badblob,publisher])
    assert fgood['txid_wire']==fbad['txid_wire']==fbase['txid_wire']
    assert fgood['wtxid_wire']!=fbad['wtxid_wire']
    # In particular Tbad still spends precisely Fgood, even when the chain
    # recorded the good rows rather than the bad ones in F's witness.
    assert tbad['outpoint']==fgood['txid_wire']+bytes(4)
    mutations=[]
    for nested in (False,True):
        for stages in (1,2,4,8):
            f0,c0=chain(goodblob,nested,stages,final)
            f1,c1=chain(badblob,nested,stages,final)
            assert all(x['txid']!=y['txid'] for x,y in zip(c0['transactions'],c1['transactions']))
            query0=tx(f0['txid_wire']+bytes(4),intended)
            query1=tx(f1['txid_wire']+bytes(4),intended)
            z0,_=bip143(query0,tail(1),999000)
            z1,_=bip143(query1,tail(1),999000)
            assert z0!=z1
            mutations.append({'before':c0,'after':c1,'old_native_scalar':f'{z0:064x}',
                'new_native_scalar':f'{z1:064x}','all_ancestor_and_funding_txids_change':True,
                'dependency_graph':graph_for(stages)})
    mode_checks=[]
    query=tx(fgood['txid_wire']+bytes(4),intended)
    changed_outpoint=bytes([query['outpoint'][0]^1])+query['outpoint'][1:]
    mutated=tx(changed_outpoint,intended)
    for flag in (1,2,3,0x81,0x82,0x83):
        z,pre=bip143(query,tail(1),999000,flag)
        zz,pree=bip143(mutated,tail(1),999000,flag)
        assert z!=zz and pre[68:104]!=pree[68:104]
        mode_checks.append({'flag':flag,'own_outpoint_offset':68,'own_outpoint_bytes':36,
            'preimage':pre.hex(),'changed_preimage':pree.hex(),'hash':f'{z:064x}','changed_hash':f'{zz:064x}'})
    result={
        'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Can a mandatory staged SegWit chain publish and authenticate recovery rows after fixing the descendant funding outpoint?',
        'scope':'Host serialization, BIP143 and ECDSA equations. Source ancestor prevout is synthetic; no Core or funded consensus validation.',
        'primary_sources':[
            'https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0141.mediawiki',
            'https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0143.mediawiki',
            'https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1477-L1534'],
        'inspection_date':'2026-09-17',
        'uncommitted_publication':{'ancestor':show(a),'F_with_intended_rows':show(fgood),'F_with_other_rows':show(fbad),
            'same_F_txid':True,'different_F_wtxid':True,'published_good_blob':goodblob.hex(),'alternative_blob':badblob.hex(),
            'ancestor_input_program':publisher.hex(),'ancestor_guard_is_row_independent':True,
            'interpretation':'Diagnostic failed candidate: immutable witness publication does not give the descendant script access to or binding to those rows.'},
        'native_descendant':{'script':final.hex(),'script_bytes':len(final),'script_code':tail(1).hex(),
            'complete_witness_items':5,'data_items':4,'hint_items':0,
            'intended_spend':show(tgood),'other_spend_of_same_F_with_other_rows':show(tbad),
            'intended_BIP143_preimage':goodpre.hex(),'other_BIP143_preimage':badpre.hex(),
            'intended_metrics':goodmetrics,'other_metrics':badmetrics,
            'actual_native_signature_checks':6,'both_accept':True,
            'no_row_binding_to_ancestor_witness':True},
        'committed_ancestor_mutations':mutations,'six_standard_BIP143_mode_outpoint_checks':mode_checks,
        'construction_found':False,'setup_under_2_64_established':False,
        'structural_scope':'Finite ancestor staging with table commitments carried only by existing P2SH/P2WSH hashes and native output-sensitive ECDSA digests. Not a lower bound for arbitrary Script evaluators or hash fixed-point searches.'}
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
