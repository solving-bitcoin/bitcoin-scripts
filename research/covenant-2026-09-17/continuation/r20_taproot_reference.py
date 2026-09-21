#!/usr/bin/env python3
"""DEFAULT input-program commitments versus mandatory shared witness data.

Raw host transaction serialization, actual BIP340/ECDSA equations, and the
existing boundary stack replay. No Bitcoin Core or complete covenant claim.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from r11_lookup_reference import P,N,G,add,mul,point,encoded,compact,execute,tail,p2sh,signature_integer,verify
from r13_table_commitment import NUMS_X, commitment, check_commitment, schnorr_sign, tagged, leaf_hash
from r10_parallel_cycles import unpack_der
sys.path.insert(0,str(HERE.parent/'seven'))
from search2_native_context import legacy_preimage


def sha(x):return hashlib.sha256(x).digest()
def h256(x):return sha(sha(x))
def vec(x):return compact(len(x))+x
def push(x):
    assert len(x)<=75
    return bytes([len(x)])+x
def b32(x):return x.to_bytes(32,'big')
def neg(q):return None if q is None else (q[0],-q[1]%P)
def outbytes(outputs):return b''.join(struct.pack('<Q',v)+vec(s) for v,s in outputs)


def serial(inputs,outputs,scripts,witnesses=None):
    vin=compact(len(inputs))+b''.join(u+vec(ss)+struct.pack('<I',seq) for (u,seq),ss in zip(inputs,scripts))
    body=vin+compact(len(outputs))+outbytes(outputs)
    base=struct.pack('<I',2)+body+bytes(4)
    w=b'' if witnesses is None else b''.join(compact(len(ws))+b''.join(vec(x) for x in ws) for ws in witnesses)
    raw=base if witnesses is None else struct.pack('<I',2)+b'\x00\x01'+body+w+bytes(4)
    return {'raw':raw,'base':base,'txid_wire':h256(base),'wtxid_wire':h256(raw),
            'witness_bytes':len(w),'weight':4*len(base)+(len(raw)-len(base))}


def show(t):
    return {'transaction_hex':t['raw'].hex(),'base_hex':t['base'].hex(),
            'txid':t['txid_wire'][::-1].hex(),'wtxid':t['wtxid_wire'][::-1].hex(),
            'total_bytes':len(t['raw']),'witness_bytes':t['witness_bytes'],'weight':t['weight']}


def default_sighash(inputs,outputs,spent,index,script):
    # Epoch0, DEFAULT0, version2, locktime0, scriptpath ext_flag1, no annex.
    m=b'\x00'+struct.pack('<II',2,0)
    m+=sha(b''.join(u for u,_ in inputs))
    m+=sha(b''.join(struct.pack('<Q',v) for v,_ in spent))
    m+=sha(b''.join(vec(s) for _,s in spent))
    m+=sha(b''.join(struct.pack('<I',q) for _,q in inputs))
    m+=sha(outbytes(outputs))
    m+=b'\x02'+struct.pack('<I',index)
    m+=leaf_hash(script)+b'\x00'+b'\xff'*4
    return tagged('TapSighash',b'\x00'+m),b'\x00'+m


def schnorr_verify(sig,key,message):
    if len(sig)!=64 or len(key)!=32:return False
    r,s=int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')
    if r>=P or s>=N:return False
    try:public=point(b'\x02'+key)
    except ValueError:return False
    e=int.from_bytes(tagged('BIP0340/challenge',sig[:32]+key+message),'big')%N
    R=add(mul(s),mul(-e,public))
    return R is not None and R[1]%2==0 and R[0]==r


def alpha(s):
    body=signature_integer(2)+signature_integer(s)
    return b'\x30'+bytes([len(body)])+body+b'\x03'


def recovery_row(sig,z):
    r,s=unpack_der(sig);flag=sig[-1]
    assert flag==3
    nonces=[]
    for x in (r,r+N):
        q=point(b'\x02'+b32(x));nonces.extend([q,neg(q)])
    keys=[encoded(mul(pow(r,-1,N),add(mul(s,R),mul(-z)))) for R in nonces[:3]]
    assert len(set(keys))==3
    assert all(verify(z,r,s,point(k))[0] for k in keys)
    return [sig]+keys



def p2sh_wrapper_peak(row,redeem,locking):
    # Explicit scriptSig pushes and the HASH160 <hash> EQUAL wrapper, before
    # the existing redeemScript replay. No consensus interpreter is claimed.
    stack=[];peak=0
    for item in row+[redeem]:stack.append(item);peak=max(peak,len(stack))
    stack[-1]=hashlib.new('ripemd160',sha(stack[-1])).digest()
    assert locking[:2]==b'\xa9\x14' and locking[-1:]==b'\x87'
    stack.append(locking[2:22]);peak=max(peak,len(stack))
    right,left=stack.pop(),stack.pop();stack.append(b'\x01' if left==right else b'')
    assert stack[-1]==b'\x01' and stack[:-1]==row
    return peak


def main():
    alpha0,alpha1=alpha(1),alpha(2)
    secret=7;pk=mul(secret);pkx=b32(pk[0])
    main_script=push(alpha0)+b'\x88'+push(pkx)+b'\xac'
    c=commitment(point(b'\x02'+b32(NUMS_X)),main_script)
    assert check_commitment(main_script,c['control'],c['script_pubkey'])
    aux=tail(1)
    spent_all=[(900000,c['script_pubkey']),(50000,p2sh(aux)),(50000,b'\x51')]
    funding=serial([(b'\x24'*32+bytes(4),0xffffffff)],spent_all,[b''])
    outpoint=lambda i:funding['txid_wire']+struct.pack('<I',i)
    inputs=[(outpoint(0),0xffffffff),(outpoint(1),0xffffffff)]
    outputs=[(940000,b'\x00\x14'+b'\x11'*20)]
    spent=spent_all[:2]
    z=2**248
    assert legacy_preimage(inputs,outputs,1,aux,3) is None
    row0,row1=recovery_row(alpha0,z),recovery_row(alpha1,z)
    msg,pre=default_sighash(inputs,outputs,spent,0,main_script)
    sig=schnorr_sign(secret,msg,11)
    assert schnorr_verify(sig,pkx,msg)
    def run_main(message,signature,claimed):
        return execute(main_script,[signature,claimed],mock_check=lambda s,k,suffix:schnorr_verify(s,k,message))
    def run_aux(row):
        def native(s,k,suffix):
            r,ss=unpack_der(s);flag=s[-1]
            assert flag==3 and legacy_preimage(inputs,outputs,1,suffix,flag) is None
            return verify(z,r,ss,point(k))[0]
        return execute(aux,row,mock_check=native)
    same_context=[]
    main_witness=[sig,alpha0,main_script,c['control']]
    for name,row in [('matching row',row0),('different auxiliary row',row1)]:
        s,a,mainmetrics=run_main(msg,sig,alpha0)
        ss,aa,auxmetrics=run_aux(row)
        assert s==ss==[b'\x01'] and not a and not aa
        scripts=[b'',b''.join(push(x) for x in row+[aux])]
        tx=serial(inputs,outputs,scripts,[main_witness,[]])
        same_context.append({'label':name,'main_claimed_alpha':alpha0.hex(),
            'auxiliary_actual_alpha':row[0].hex(),'auxiliary_data_matches_main_claim':row[0]==alpha0,
            'all_native_checks_pass':True,'auxiliary_row':list(map(bytes.hex,row)),
            'transaction':show(tx),'main_metrics':mainmetrics,'aux_metrics':auxmetrics,
            'auxiliary_script_sig_bytes':len(scripts[1]),'auxiliary_script_sig_pushes':len(row)+1,
            'main_witness_items':4,'main_data_items':2,'main_hint_items':0,
            'aux_data_items':4,'aux_hint_items':0,'aux_witness_items':0,
            'aux_redeem_fragment_peak':auxmetrics['combined_stack_peak'],
            'aux_complete_P2SH_peak':max(auxmetrics['combined_stack_peak'],p2sh_wrapper_peak(row,aux,spent_all[1][1])),'aux_complete_P2SH_nonpush_ops':auxmetrics['counted_opcodes']+2})
    assert same_context[0]['transaction']['txid']!=same_context[1]['transaction']['txid']
    # Actual alternate sibling input: outpoint and scriptPubKey both change.
    replacement=[inputs[0],(outpoint(2),0xffffffff)]
    replacement_spent=[spent_all[0],spent_all[2]]
    altmsg,altpre=default_sighash(replacement,outputs,replacement_spent,0,main_script)
    assert altmsg!=msg and not schnorr_verify(sig,pkx,altmsg)
    altsig=schnorr_sign(secret,altmsg,19)
    s,a,altmetrics=run_main(altmsg,altsig,alpha0)
    assert s==[b'\x01'] and not a
    alttransaction=serial(replacement,outputs,[b'',b''],[[altsig,alpha0,main_script,c['control']],[]])
    # The replacement spent script is exactly OP_TRUE and requires no data.
    ss,aa,truemetrics=execute(b'\x51',[])
    assert ss==[b'\x01'] and not aa
    negatives=[]
    for name,thunk in [('main alpha changed',lambda:run_main(msg,sig,alpha1)),
                        ('changed alpha with old auxiliary keys',lambda:run_aux([alpha1]+row0[1:]))]:
        try:thunk()
        except ValueError as error:negatives.append({'case':name,'rejected':True,'reason':str(error)})
        else:raise AssertionError(name)
    negatives.append({'case':'old DEFAULT signature after auxiliary replacement','rejected':not schnorr_verify(sig,pkx,altmsg)})
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Does a Taproot DEFAULT commitment to all input scriptPubKeys itself force an auxiliary checker and shared witness data?',
        'scope':'Synthetic-parent, fully serialized two-input host fixture. Actual Schnorr/ECDSA equations and raw stack replay; no Bitcoin Core or covenant claim.',
        'sources':['https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#common-signature-message',
                   'https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki'],
        'funding':show(funding),'main_leaf':main_script.hex(),'main_leaf_bytes':len(main_script),
        'main_control':c['control'].hex(),'main_spent_script':spent_all[0][1].hex(),
        'NUMS_internal_key':f'{NUMS_X:064x}','known_leaf_signing_scalar':secret,
        'auxiliary_redeem_script':aux.hex(),'auxiliary_script_bytes':len(aux),
        'auxiliary_spent_script':spent_all[1][1].hex(),'native_aux_digest_scalar':str(z),
        'DEFAULT_preimage':pre.hex(),'DEFAULT_message':msg.hex(),'same_DEFAULT_signature':sig.hex(),
        'same_signature_two_auxiliary_rows':same_context,
        'main_witness_serialized_bytes':len(compact(len(main_witness))+b''.join(vec(x) for x in main_witness)),
        'main_validation_budget_consumed':50,
        'main_validation_budget_available':50+len(compact(len(main_witness))+b''.join(vec(x) for x in main_witness)),
        'locking_output_bytes':{'taproot_scriptPubKey':len(spent_all[0][1]),'P2SH_scriptPubKey':len(spent_all[1][1])},
        'explicit_auxiliary_program_replacement':{'same_funding':True,'same_main_outpoint':True,
            'new_auxiliary_spent_script':'51','new_DEFAULT_preimage':altpre.hex(),'new_DEFAULT_message':altmsg.hex(),
            'old_signature_rejects':True,'fresh_public_key_signature_accepts':True,
            'new_signature':altsig.hex(),'transaction':show(alttransaction),
            'main_metrics':altmetrics,'replacement_metrics':truemetrics},
        'negative_controls':negatives,
        'not_claimed':['Mandatory-reference covenant','Hash-derived provenance of the auxiliary alpha',
                       'SIGHASH_SINGLE output binding','Bitcoin consensus or relay validation'],
        'all_assertions_passed':True}
    (HERE/'r20_taproot_reference.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'same_context_variants':len(same_context),'main_script':len(main_script),
        'aux_script':len(aux),'different_auxiliary_row_accepts':True,
        'public_resigning_auxiliary_replacement_accepts':True,'negative_controls':len(negatives)},indent=2))


if __name__=='__main__':main()
