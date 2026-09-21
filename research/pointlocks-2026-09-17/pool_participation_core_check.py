#!/usr/bin/env python3
"""Check complete and partial spends of the same funded 95-pool public fixture.

The creator retains the deterministic fixture secrets and re-signs each chosen
input set. This tests participation, not the unknown-nonce extraction problem.
Only a disposable regtest node with networking and wallets disabled is used.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import (isolated_core_binary, Node, consensus_check, transaction,
                        instructions, unpack_signature, decode_key, compact_size, vector)
from publication_core_check import accept_and_mine, encode_key, hash160
from anchored_native_core_check import digest
from round_major_publication_core_check import straight_line_stack_peak
from legacy_same_signature_counterexample import N, G, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = HERE / 'round-major-publication-transactions.json'
EXAMPLE = 'pointlock_pool_participation_probe'


def recover_partial(funding, tx, manifest, metrics):
    """Read actual public witnesses; fixture secrets are not inputs to extraction."""
    records = []
    equations = 0
    resource_rows = []
    for item in metrics['pools']:
        pool_id, index = item['pool'], item['input_index']
        pool = manifest['pools'][pool_id]
        vin = tx['vin'][index]
        assert vin['txid'] == funding['txid'] and vin['vout'] == pool_id + 1
        witness = [bytes.fromhex(v) for v in vin['txinwitness']]
        witness_bytes = len(compact_size(len(witness))) + sum(len(vector(v)) for v in witness)
        assert len(witness) == item['complete_witness_items'] == 47
        assert witness_bytes == item['serialized_witness_bytes']
        script = witness.pop()
        assert script.hex() == pool['script_hex']
        assert funding['vout'][pool_id+1]['scriptPubKey']['hex'] == '0020' + hashlib.sha256(script).hexdigest()
        auth = witness.pop()
        r, s, flag = unpack_signature(auth)
        assert flag == 1 and verify(int.from_bytes(digest(tx,index,script,flag),'big'),r,s,G)[0]
        equations += 1
        contexts = []
        start = 0
        table = []
        for _, end, op, data in instructions(script):
            if data is not None and len(data) == 20:
                table.append(data)
            if op == 0xab:
                start = end
            elif op == 0xad:
                contexts.append(script[start:])
        assert len(table) == len(set(table)) == 54 and len(contexts) == 36
        assert table == [hash160(bytes.fromhex(v)) for v in pool['tau_table']]
        stream = list(reversed(witness))
        assert len(stream) == 45
        remaining = list(range(54))
        selected, anchors = [], []
        for slot in range(5):
            tau, hint = stream[2*slot:2*slot+2]
            assert len(hint) == 1
            depth = hint[0]
            assert 1 <= depth <= len(remaining)
            label = remaining.pop(len(remaining)-depth)
            assert hash160(tau) == table[label]
            selected.append(label)
            anchors.append(tau)
        assert selected == item['selected'] == pool['selected']
        for slot, (label, tau) in enumerate(reversed(list(zip(selected,anchors)))):
            key = decode_key(stream[40+slot])
            rt, st, flag = unpack_signature(tau)
            assert len(tau) == 40 and st == flag == 1
            target = bytes.fromhex(pool['targets'][label])
            assert rt == decode_key(target)[0]
            z0 = int.from_bytes(digest(tx,index,contexts[1+slot],flag),'big') % N
            assert verify(z0,rt,st,key)[0]
            equations += 1
            candidates = []
            for round_index in range(6):
                sig = stream[10+5*round_index+slot]
                r, s, flag = unpack_signature(sig)
                assert len(sig) == 60
                z = int.from_bytes(digest(tx,index,contexts[6+5*round_index+slot],flag),'big') % N
                assert verify(z,r,s,key)[0]
                equations += 1
                matches = []
                for k in ((N+1)//2,(N-1)//2):
                    secret = (s*k-z)*pow(r,-1,N) % N
                    if mul(secret) != key:
                        continue
                    for sign in (1,-1):
                        scalar = sign*(rt*secret+z0) % N
                        if encode_key(mul(scalar)) == target:
                            matches.append(scalar)
                assert len(matches) == 1
                candidates.append(matches[0])
            assert len(set(candidates)) == 1
            records.append(dict(pool=pool_id,label=label,target=target.hex(),scalar=f'{candidates[0]:064x}'))
        resource_rows.append(dict(pool=pool_id,script_bytes=len(script),
            static_non_push_opcodes=sum(op > 0x60 for _,_,op,data in instructions(script) if data is None),
            hint_items=5,entry_items=46,complete_witness_items=47,
            serialized_witness_bytes=witness_bytes,
            combined_stack_peak_static_trace=straight_line_stack_peak(script,46)))
    return dict(extractions=records,extracted_points=len(records),ecdsa_equations_checked=equations,
                complete_256_byte_message=False,resources=resource_rows)


def main():
    manifest_bytes = MANIFEST.read_bytes()
    manifest = json.loads(manifest_bytes)
    old_report = json.loads((HERE/'round_major_publication_core_check.json').read_text())
    assert old_report['transactions_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report = dict(scope=__doc__,evidence='differentially-validated',deployment='policy-validated',
                  bitcoin_core=provenance,cases=[],all_consensus_extraction_established=False,
                  application_theft_demonstrated=False)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-pool-participation-') as temporary:
        node = Node(binary,Path(temporary))
        try:
            node.ready()
            report['node_options'] = node.options
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address = node.rpc('decodescript','51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress',1,address)
            coinbase = node.rpc('getblock',blocks[0],2)['tx'][0]
            coin = next(v for v in coinbase['vout'] if v['scriptPubKey']['hex'] == mining.hex())
            grant = transaction(coinbase['txid'],coin['n'],[b'\x51'],[
                (100_000_000,b'\x51\x20'+G[0].to_bytes(32,'big')),
                (5_000_000_000-100_000_000-10_000,mining)])
            granted, report['excluded_test_grant'] = accept_and_mine(node,address,grant['hex'])
            command = ['cargo','run','--release','--locked','--example',EXAMPLE,'--',str(MANIFEST),granted['txid']]
            run = subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=True)
            built = json.loads(run.stdout)
            report['generator_command'] = command
            report['generator_stderr'] = run.stderr
            funding,report['funding'] = accept_and_mine(node,address,built['funding']['hex'])
            assert len(funding['vout']) == 96
            for pool in manifest['pools']:
                assert funding['vout'][pool['pool']+1]['scriptPubKey']['hex'] == '0020'+hashlib.sha256(bytes.fromhex(pool['script_hex'])).hexdigest()
            print('PASS unchanged 95 pool outputs funded',flush=True)
            # Snapshot policy before any conflicting positive is mined/rolled back.
            for case in built['cases']:
                policy = node.rpc('testmempoolaccept',[case['transaction']['hex']])[0]
                assert policy['allowed'] == case['expected'],(case['name'],policy)
                report['cases'].append(dict(**case,policy=policy))
            height = node.rpc('getblockcount')
            for case in report['cases']:
                decoded = node.rpc('decoderawtransaction',case['transaction']['hex'])
                assert decoded['vsize'] == case['transaction']['vbytes']
                assert decoded['weight'] == case['transaction']['weight']
                result = consensus_check(node,address,case['transaction'])
                assert result['accepted'] == case['expected'],(case['name'],result)
                case['consensus'] = result
                if result['accepted']:
                    if case['name'] != 'full-95-pool-control':
                        recovery = recover_partial(funding,decoded,manifest,case['metrics'])
                        assert recovery['extracted_points'] == 5
                        # Check against the old private fixtures only after public extraction.
                        for record in recovery['extractions']:
                            frame = next(f for f in manifest['pools'][record['pool']]['frames'] if f['selected'] == record['label'])
                            assert frame['target_scalar_fixture'] == record['scalar']
                        case['public_recovery'] = recovery
                        pool_id = case['metrics']['pools'][0]['pool']
                        remaining = [v for v in range(1,96) if node.rpc('gettxout',funding['txid'],v,False) is not None]
                        assert remaining == [v for v in range(1,96) if v != pool_id+1]
                        helper_unspent = node.rpc('gettxout',funding['txid'],0,False) is not None
                        assert helper_unspent == (not case['metrics']['includes_helper'])
                        case['after_mining'] = dict(unspent_pool_outputs=remaining,helper_unspent=helper_unspent)
                    else:
                        report['full_control_combined_vbytes'] = funding['vsize']+decoded['vsize']
                        assert report['full_control_combined_vbytes'] < 100_000
                    node.rpc('invalidateblock',result['block_hash'])
                assert node.rpc('getblockcount') == height
                print('PASS',case['name'],'accepted' if case['expected'] else 'rejected',flush=True)
            report['summary'] = dict(positive_cases=5,negative_cases=3,
                partial_spends_accepted=4,unopened_pools_per_partial=94,all_expectations_met=True)
        finally:
            node.close()
    paths = [Path(__file__),ROOT/f'examples/{EXAMPLE}.rs',ROOT/'Cargo.lock',ROOT/'tools/core_regtest.py',
             HERE/'core_check.py',HERE/'publication_core_check.py',HERE/'anchored_native_core_check.py',
             HERE/'round_major_publication_core_check.py',HERE/'round_major_publication_core_check.json',
             MANIFEST,HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py',
             ROOT/'src/signatures/pointlocks/mod.rs']
    report['source_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report['generator_binary_sha256'] = hashlib.sha256((ROOT/f'target/release/examples/{EXAMPLE}').read_bytes()).hexdigest()
    (HERE/'pool-participation-core-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['summary']),flush=True)


if __name__ == '__main__':
    main()
