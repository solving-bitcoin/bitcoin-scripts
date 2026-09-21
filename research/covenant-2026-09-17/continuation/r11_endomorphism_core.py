#!/usr/bin/env python3
"""Funded Core checks of free-signature endomorphism pairs.

Same P2SH outpoint, SINGLE and ALL on its second input, publicly recomputed
witnesses for different outputs. No hash-derived alpha or covenant is claimed.
"""
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary, p2sh, push
import core_regtest
from core_regtest import Node, consensus_check, transaction
from r5_root_core import wait_restarted
from r11_endomorphism import C, N, add, mul, neg, hash256, layout, solve, signature, pubkey, run_layout


def compact(n):
    return bytes([n]) if n < 253 else b'\xfd'+struct.pack('<H', n)


def vector(data):
    return compact(len(data))+data


def base_tx(txid, second_script, outputs, locktime):
    raw = struct.pack('<I', 2)+b'\x02'
    # Ordinary OP_TRUE P2WSH input first; locked P2SH input second.
    for vout, script in ((1, b''), (0, second_script)):
        raw += bytes.fromhex(txid)[::-1]+struct.pack('<I', vout)+vector(script)+b'\xff'*4
    raw += compact(len(outputs))
    raw += b''.join(struct.pack('<Q', amount)+vector(script) for amount, script in outputs)
    return raw+struct.pack('<I', locktime)


def spend_tx(txid, script_sig, outputs, locktime):
    base = base_tx(txid, script_sig, outputs, locktime)
    witnesses = b'\x01\x01\x51\x00'
    raw = base[:4]+b'\x00\x01'+base[4:-4]+witnesses+base[-4:]
    return {'hex': raw.hex(), 'txid': hash256(base)[::-1].hex(),
            'wtxid': hash256(raw)[::-1].hex(), 'base_bytes': len(base),
            'total_bytes': len(raw), 'witness_bytes': len(witnesses),
            'marker_flag_bytes': 2, 'weight': 4*len(base)+len(witnesses)+2}


def witness(txid, outputs):
    script = layout()
    attempts = []
    for locktime in range(128):
        preimage = base_tx(txid, script, outputs, locktime)+struct.pack('<I', 1)
        digest = hash256(preimage)
        z = int.from_bytes(digest, 'big') % N
        if z == 0: continue
        found = solve(z*pow(C, -1, N) % N)
        attempts.append({'locktime': locktime, 'digest': digest.hex(), 'found': found is not None})
        if found is None: continue
        r, rp, t, root = found['r_alpha'], found['r_beta'], found['t'], found['R_alpha']
        assert mul(t, root) == found['R_beta']
        s = rp*pow(t*r, -1, N) % N
        s = min(s, N-s)
        keys = [mul(pow(r, -1, N), add(point, mul(-C))) for point in (root, neg(root))]
        if any(q is None for q in keys): continue
        data = [signature(r, 1, 3), signature(rp, s, 1)]+[pubkey(q) for q in keys]
        assert len(set(data[2:])) == 2
        trace = run_layout(script, data, [C, C, z, z])
        assert trace == {'checks': 4, 'combined_stack_peak': 7, 'executed_non_push_opcodes': 27}
        return data, {'locktime': locktime, 'all_preimage': preimage.hex(),
                      'all_digest': digest.hex(), 'single_bug_digest': (b'\x01'+bytes(31)).hex(),
                      'solution': found, 'attempts': attempts, 'beta_s': s, 'trace': trace}
    raise RuntimeError('Bounded endomorphism witness search exhausted')


def main():
    script = layout()
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = {'scope': __doc__, 'bitcoin_core': provenance, 'redeemscript': script.hex(),
              'redeemscript_bytes': 44, 'p2sh_locking_script_bytes': 23, 'results': []}
    with tempfile.TemporaryDirectory(prefix='covenant-r11-endomorphism-') as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick(); blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(o for o in coinbase['vout'] if o['scriptPubKey']['hex'] == mining.hex())
            funding = transaction(coinbase['txid'], coin['n'], [b'\x51'],
                                  [(1000000, p2sh(script)), (1000000, mining), (4997990000, mining)])
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding

            def check(name, data, details, outputs, expected):
                nonlocal node
                assert node.rpc('getrawmempool') == []
                script_sig = b''.join(push(item) for item in data)+push(script)
                tx = spend_tx(funding['txid'], script_sig, outputs, details['locktime'])
                decoded = node.rpc('decoderawtransaction', tx['hex'])
                assert decoded['txid'] == tx['txid'] and decoded['weight'] == tx['weight']
                policy = node.rpc('testmempoolaccept', [tx['hex']])[0]
                consensus = consensus_check(node, address, tx)
                assert policy['allowed'] == expected and consensus['accepted'] == expected, (name, policy, consensus)
                actual_preimage = base_tx(funding['txid'], script, outputs, details['locktime'])+struct.pack('<I', 1)
                report['results'].append({'name': name, 'input_data_items': 4, 'hint_items': 0,
                    'script_sig_push_items': 5, 'script_sig_bytes': len(script_sig),
                    'locked_input_witness_items': 0, 'ordinary_input_witness_items': 1,
                    'complete_transaction_witness_bytes': 4, 'marker_flag_bytes': 2,
                    'combined_stack_peak_if_success': 7 if expected else None,
                    'redeem_executed_non_push_opcodes_if_success': 27 if expected else None,
                    'p2sh_additional_opcodes_if_success': 2 if expected else None,
                    'input_items': [x.hex() for x in data],
                    'outputs': [{'amount': a, 'script': s.hex()} for a, s in outputs],
                    'transaction': tx, 'policy': policy, 'consensus': consensus, **details,
                    'all_preimage_digest_trace_scope': 'Original witness construction; the actual test transaction uses the actual_all_* fields.',
                    'actual_all_preimage': actual_preimage.hex(),
                    'actual_all_digest': hash256(actual_preimage).hex(),
                    'evidence': 'differentially-validated',
                    'deployment_class': 'policy-validated' if expected else 'consensus-incompatible'})
                print('PASS', name, 'accepted=', expected, flush=True)
                if expected:
                    node.rpc('invalidateblock', consensus['block_hash'])
                    mocktime, height = node.mocktime, node.rpc('getblockcount')
                    node.close()
                    old = core_regtest.START_TIME
                    core_regtest.START_TIME = mocktime
                    try: node = Node(binary, Path(tmp))
                    finally: core_regtest.START_TIME = old
                    wait_restarted(node, height)
                    node.mocktime = mocktime
                    node.rpc('setmocktime', mocktime)

            outputs_a = [(1990000, b'\x00\x14'+b'\x11'*20)]
            outputs_b = [(1990000, b'\x00\x14'+b'\x22'*20)]
            outputs_c = [(1980000, b'\x00\x14'+b'\x33'*20)]
            data_a, details_a = witness(funding['txid'], outputs_a)
            check('recipient-a', data_a, details_a, outputs_a, True)
            check('changed-output-old-witness', data_a, details_a, outputs_b, False)
            data_b, details_b = witness(funding['txid'], outputs_b)
            check('recipient-b-recomputed-public-witness', data_b, details_b, outputs_b, True)
            data_c, details_c = witness(funding['txid'], outputs_c)
            check('amount-and-recipient-c-recomputed-public-witness', data_c, details_c, outputs_c, True)
            check('duplicate-key', data_a[:3]+[data_a[2]], details_a, outputs_a, False)
            changed = [signature(details_a['solution']['r_alpha'], 2, 3)]+data_a[1:]
            check('changed-alpha-s', changed, details_a, outputs_a, False)
            report['all_expectations_met'] = True
        finally:
            node.close()
    path = Path(__file__).with_suffix('.json')
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(path)


if __name__ == '__main__':
    main()
