#!/usr/bin/env python3
"""Fund one anchored native point-lock candidate and check CODESEPARATOR on Core.

Honest functionality/differential evidence only; no general extraction proof.
Network and wallets are disabled. All keys belong to public deterministic tests.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from core_check import isolated_core_binary, Node, consensus_check, transaction, instructions, unpack_signature, decode_key
from publication_core_check import accept_and_mine, encode_key
from legacy_same_signature_counterexample import N, G, mul, verify, hash256
from core_regtest import compact_size, vector

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def build(funding_txid=None):
    cmd = ['cargo', 'run', '--locked', '--example', 'pointlock_anchored_native_probe',
           '--', '--seed', '0', '--repetitions', '5']
    if funding_txid:
        cmd += ['--funding-txid', funding_txid]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=True)
    return json.loads(result.stdout), result.stderr


def outbytes(output):
    return (struct.pack('<Q', round(output['value'] * 100_000_000))
            + vector(bytes.fromhex(output['scriptPubKey']['hex'])))


def digest(tx, index, code, flag):
    base = flag & 31
    previous = b''.join(bytes.fromhex(v['txid'])[::-1] + struct.pack('<I', v['vout']) for v in tx['vin'])
    hp = bytes(32) if flag & 128 else hash256(previous)
    hs = (hash256(b''.join(struct.pack('<I', v['sequence']) for v in tx['vin']))
          if not flag & 128 and base not in (2, 3) else bytes(32))
    ho = bytes(32)
    if base not in (2, 3):
        ho = hash256(b''.join(outbytes(v) for v in tx['vout']))
    elif base == 3 and index < len(tx['vout']):
        ho = hash256(outbytes(tx['vout'][index]))
    own = tx['vin'][index]
    preimage = (struct.pack('<I', tx['version']) + hp + hs
                + bytes.fromhex(own['txid'])[::-1] + struct.pack('<I', own['vout'])
                + vector(code) + struct.pack('<Q', 100_000)
                + struct.pack('<I', own['sequence']) + ho
                + struct.pack('<II', tx['locktime'], flag))
    return hash256(preimage)


def independently_recover(tx, case):
    script = bytes.fromhex(case['script_hex'])
    witness = [bytes.fromhex(v) for v in tx['vin'][1]['txinwitness']]
    assert witness.pop() == script
    point = decode_key(witness.pop())
    signatures = list(reversed(witness))
    tau = next(data for _, _, _, data in instructions(script) if data is not None and len(data) == 40)
    rt, st, flag = unpack_signature(tau)
    assert st == flag == 1
    z0_bytes = digest(tx, 1, script, flag)
    assert z0_bytes.hex() == case['anchor_digest']
    z0 = int.from_bytes(z0_bytes, 'big') % N
    assert verify(z0, rt, st, point)[0]
    suffixes = [script[end:] for _, end, op, _ in instructions(script) if op == 0xab]
    recovered = []
    target = bytes.fromhex(case['target'])
    for i, (sigma, code) in enumerate(zip(signatures, suffixes)):
        r, s, flag = unpack_signature(sigma)
        assert len(sigma) == 60
        msg = digest(tx, 1, code, flag)
        assert msg.hex() == case['short_digests'][i]
        z = int.from_bytes(msg, 'big') % N
        assert verify(z, r, s, point)[0]
        assert r == int('3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63', 16)
        matching = []
        for k in ((N + 1)//2, (N - 1)//2):
            p = ((s*k-z)*pow(r, -1, N)) % N
            if mul(p) != point:
                continue
            for sign in (1, -1):
                t = (sign*(rt*p+z0)) % N
                if encode_key(mul(t)) == target:
                    matching.append(t)
        assert len(matching) == 1
        assert f'{matching[0]:064x}' == case['target_scalar_fixture']
        recovered.append(f'{matching[0]:064x}')
    assert len(recovered) == case['repetitions']
    return dict(signature_checks=1+len(signatures), extracted_scalars=recovered,
                original_target=case['target'])


def main():
    template, _ = build()
    script = bytes.fromhex(template['cases'][0]['script_hex'])
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = dict(scope=__doc__, bitcoin_core=provenance,
                  evidence='differentially-validated', deployment_class='policy-validated',
                  negative_cases=[], extraction_soundness_established=False)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-anchored-native-') as temporary:
        node = Node(binary, Path(temporary))
        try:
            node.ready()
            report['node_options'] = node.options
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(v for v in coinbase['vout'] if v['scriptPubKey']['hex'] == mining.hex())
            fund = transaction(coinbase['txid'], coin['n'], [b'\x51'], [
                (100_000, mining), (100_000, b'\x00\x20' + hashlib.sha256(script).digest()),
                (5_000_000_000 - 210_000, mining)])
            funding, report['test_fixture_funding'] = accept_and_mine(node, address, fund['hex'])
            built, report['rust_generation_stderr'] = build(funding['txid'])
            (HERE/'anchored-native-transactions.json').write_text(json.dumps(built, indent=2)+'\n')
            case = built['cases'][0]
            assert case['script_hex'] == script.hex()
            assert not case['local_correct_native_accepted']
            assert case['local_incorrect_separator_including_accepted']
            negative = case['negative_cases'] + [{
                'name': 'including-executed-separator-in-digest',
                'transaction': case['incorrect_separator_including_transaction']}]
            for item in negative:
                tx = item['transaction']
                policy = node.rpc('testmempoolaccept', [tx['hex']])[0]
                consensus = consensus_check(node, address, tx)
                assert not policy['allowed'] and not consensus['accepted'], item['name']
                report['negative_cases'].append(dict(name=item['name'], policy=policy, consensus=consensus))
                print('PASS negative', item['name'], flush=True)
            spend, report['spending'] = accept_and_mine(node, address, case['correct_native_transaction']['hex'])
            report['recovery'] = independently_recover(spend, case)
            report['local_interpreter'] = dict(correct_native_accepted=False, incorrect_separator_including_accepted=True)
            report['metrics'] = {k: case[k] for k in ['repetitions', 'script_bytes', 'tau_bytes',
                'hint_items', 'entry_items', 'complete_witness_items', 'serialized_witness_bytes']}
            report['all_expectations_met'] = True
            print('PASS actual native anchor plus five separated short-signature checks', flush=True)
        finally:
            node.close()
    (HERE/'anchored_native_core_check.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
