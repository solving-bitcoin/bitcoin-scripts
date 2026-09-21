#!/usr/bin/env python3
"""Check every raw ECDSA sighash byte in the actual cap60/five-context script.

Known-G/2 honest openings only, not a non-extracting attack. Each competing
spend is block-validated and mined, then its block is invalidated on this
disposable network-disabled regtest chain to restore the same test outputs.
"""
import hashlib
import argparse
import json
from pathlib import Path
import struct
import tempfile

from anchored_native_core_check import build, digest, outbytes
from core_check import isolated_core_binary, Node, transaction, consensus_check, instructions, unpack_signature
from core_regtest import compact_size, vector
from publication_core_check import accept_and_mine, encode_key
from legacy_same_signature_counterexample import N, mul, hash256
from anchored_extraction import der, HALF, HALF_R
from anchored_extraction import extract, decode_verification_key
from anchored_publication_core_check import straight_line_stack_peak

HERE = Path(__file__).resolve().parent
STANDARD = {1, 2, 3, 129, 130, 131}


def serialized(tx):
    base = struct.pack('<I', tx['version']) + compact_size(len(tx['vin']))
    for vin in tx['vin']:
        base += bytes.fromhex(vin['txid'])[::-1] + struct.pack('<I', vin['vout'])
        base += vector(bytes.fromhex(vin['scriptSig']['hex'])) + struct.pack('<I', vin['sequence'])
    base += compact_size(len(tx['vout'])) + b''.join(outbytes(out) for out in tx['vout'])
    base += struct.pack('<I', tx['locktime'])
    witness = b''
    for vin in tx['vin']:
        items = [bytes.fromhex(item) for item in vin['txinwitness']]
        witness += compact_size(len(items)) + b''.join(vector(item) for item in items)
    raw = base[:4] + b'\x00\x01' + base[4:-4] + witness + base[-4:]
    weight = len(base)*3 + len(raw)
    return dict(hex=raw.hex(), txid=hash256(base)[::-1].hex(), weight=weight, vbytes=(weight+3)//4)


def make_case(template, script, t, flag, key_encoding='compressed'):
    # Deep copy the Core-decoded actual transaction. The own-input sequence is
    # included in every raw-flag BIP143 preimage and supplies honest retries.
    tx = json.loads(json.dumps(template))
    tau = next(data for _, _, _, data in instructions(script) if data is not None and len(data) == 40)
    rt, _, anchor_flag = unpack_signature(tau)
    assert anchor_flag == 1
    contexts = [script[end:] for _, end, op, _ in instructions(script) if op == 0xab]
    for attempt in range(100):
        tx['vin'][1]['sequence'] = 0xffffffff-attempt
        anchor = digest(tx, 1, script, 1)
        p = (t-int.from_bytes(anchor, 'big')) * pow(rt, -1, N) % N
        if not p:
            continue
        signatures = []
        for code in contexts:
            msg = digest(tx, 1, code, flag)
            s = (int.from_bytes(msg, 'big') + HALF_R*p) * 2 % N
            s = min(s, N-s)
            sigma = der(HALF_R, s)[:-1] + bytes([flag])
            if len(sigma) != 60:
                break
            # Scalar extraction must still recover the known target in this
            # diagnostic. Neither the flag nor the positive Core verdict is
            # being credited as a non-extracting attack.
            found = []
            for nonce in (HALF, -HALF % N):
                pp = (s*nonce-int.from_bytes(msg, 'big')) * pow(HALF_R, -1, N) % N
                if pp == p:
                    found.append((rt*pp+int.from_bytes(anchor, 'big')) % N)
            assert found == [t]
            signatures.append(sigma)
        if len(signatures) == len(contexts):
            tx['vin'][1]['txinwitness'] = [item.hex() for item in reversed(signatures)]
            point = mul(p)
            key = encode_key(point)
            if key_encoding != 'compressed':
                prefix = 4 if key_encoding == 'uncompressed' else 6+point[1]%2
                key = bytes([prefix])+point[0].to_bytes(32, 'big')+point[1].to_bytes(32, 'big')
            assert decode_verification_key(key) == point
            tx['vin'][1]['txinwitness'] += [key.hex(), script.hex()]
            recovered = extract(tau, anchor, key, encode_key(mul(t)),
                                [(sigma, digest(tx, 1, code, flag)) for sigma, code in zip(signatures, contexts)])
            assert recovered['scalar'] == t
            return dict(flag=flag, transaction=serialized(tx), attempts=attempt+1,
                        key_encoding=key_encoding, signature_flags=[flag]*len(signatures),
                        key_bytes=len(key), serialized_witness_bytes=len(compact_size(len(tx['vin'][1]['txinwitness'])))+sum(len(vector(bytes.fromhex(v))) for v in tx['vin'][1]['txinwitness']),
                        extracted_target=f'{t:064x}')
    raise AssertionError('unexpected diagnostic retry exhaustion')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-encodings-only', action='store_true')
    args = parser.parse_args()
    initial, _ = build()
    script = bytes.fromhex(initial['cases'][0]['script_hex'])
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = dict(scope=__doc__, bitcoin_core=provenance, evidence='differentially-validated',
                  deployment_class='consensus-validated', extraction_attack=False, cases=[])
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-anchor-flags-') as temporary:
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
                (100_000, mining), (100_000, b'\x00\x20'+hashlib.sha256(script).digest()),
                (5_000_000_000-210_000, mining)])
            funding, report['test_fixture_funding'] = accept_and_mine(node, address, fund['hex'])
            built, _ = build(funding['txid'])
            case = built['cases'][0]
            template = node.rpc('decoderawtransaction', case['correct_native_transaction']['hex'])
            t = int(case['target_scalar_fixture'], 16)
            cases = ([make_case(template, script, t, 1, encoding) for encoding in ('uncompressed', 'hybrid')]
                     if args.key_encodings_only else [make_case(template, script, t, flag) for flag in range(256)])
            # Evaluate all mempool policies before block resets can reinsert a
            # conflicting standard spend into the private node's mempool.
            for item in cases:
                policy = node.rpc('testmempoolaccept', [item['transaction']['hex']])[0]
                assert policy['allowed'] == (item['flag'] in STANDARD and item['key_encoding'] == 'compressed'), item['flag']
                if not policy['allowed'] and item['key_encoding'] == 'compressed':
                    assert 'hash type' in policy['reject-reason'].lower(), policy
                item['policy'] = policy
            base_height = node.rpc('getblockcount')
            for item in cases:
                result = consensus_check(node, address, item['transaction'])
                assert result['accepted'], item['flag']
                item['consensus'] = result
                node.rpc('invalidateblock', result['block_hash'])
                assert node.rpc('getblockcount') == base_height
                if item['flag'] % 32 == 31:
                    print(f'PASS raw sighash bytes 0..{item["flag"]}: consensus accepted', flush=True)
            report['cases'] = cases
            policy_count=sum(item['policy']['allowed'] for item in cases)
            report['summary'] = dict(consensus_accepted=len(cases), policy_accepted=policy_count,
                policy_rejected=len(cases)-policy_count, script_bytes=len(script), hint_items=0,
                entry_items=6, complete_witness_items=7, signatures_per_spend=6,
                combined_stack_peak_static_trace=straight_line_stack_peak(script,6))
            report['all_expectations_met'] = True
        finally:
            node.close()
    filename = 'anchored_consensus_keys_check.json' if args.key_encodings_only else 'anchored_consensus_flags_check.json'
    (HERE/filename).write_text(json.dumps(report, indent=2)+'\n')
    print(report['summary'], flush=True)


if __name__ == '__main__':
    main()
