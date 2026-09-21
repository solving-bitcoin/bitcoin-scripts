#!/usr/bin/env python3
"""Replay the existing full point-lock fixture through the graph extractor.

bitcoin-tx decodes actual serialized transactions offline. The historical
Core acceptance report and its pins are checked, not rerun or strengthened.
No generator private scalar cache or supplied digest is used for extraction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from core_check import decode_key, instructions, unpack_signature
from publication_core_check import encode_key, hash160
from anchored_native_core_check import digest
from windowed_native_core_check import rank_subset
from cross_key_nonce_extraction import N, G, mul, verify, analyze_publication

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(binary):
    artifact = HERE/'round-major-publication-transactions.json'
    historical_path = HERE/'round_major_publication_core_check.json'
    built = json.loads(artifact.read_text())
    historical = json.loads(historical_path.read_text())
    assert sha(artifact) == historical['transactions_sha256']
    for name, expected in historical['source_sha256'].items():
        assert sha(ROOT/name) == expected, f'changed native source: {name}'
    for pool in built['pools']:
        del pool['frames']  # Contains fixture secrets/digests: never an extractor input.

    def decode(name):
        raw = built[name]['hex']
        output = subprocess.run([str(binary), '-json', '-'], input=raw,
                                text=True, capture_output=True, check=True)
        decoded = json.loads(output.stdout)
        previous = historical['spending' if name == 'spending' else 'funding']
        assert decoded['hex'] == raw == previous['hex']
        assert decoded['txid'] == previous['txid']
        assert decoded['vsize'] == previous['vsize']
        assert previous['consensus_accepted'] and previous['policy']['allowed']
        return decoded

    funding, spend = decode('funding'), decode('spending')
    keys, rows, targets, digits = [], [], [], []
    assert len(spend['vin']) == len(funding['vout']) == built['pool_count'] + 1
    assert built['pool_count'] == 95
    for pool in built['pools']:
        index, threshold, rounds = pool['input_index'], pool['t'], pool['rounds']
        vin = spend['vin'][index]
        assert vin['txid'] == funding['txid'] and vin['vout'] == index
        assert round(funding['vout'][index]['value'] * 100_000_000) == 100_000
        witness = [bytes.fromhex(v) for v in vin['txinwitness']]
        script, auth = witness.pop(), witness.pop()
        assert script.hex() == pool['script_hex']
        assert funding['vout'][index]['scriptPubKey']['hex'] == '0020' + hashlib.sha256(script).hexdigest()
        ra, sa, flag = unpack_signature(auth)
        assert flag == 1 and verify(int.from_bytes(digest(spend, index, script, flag), 'big'), ra, sa, G)[0]
        table = [data for _, _, _, data in instructions(script) if data is not None and len(data) == 20]
        assert table == [hash160(bytes.fromhex(tau)) for tau in pool['tau_table']]
        assert len(table) == len(set(table)) == pool['n']
        contexts, start = [], 0
        for _, end, opcode, _ in instructions(script):
            if opcode == 0xab:
                start = end
            elif opcode == 0xad:
                contexts.append(script[start:])
        assert len(contexts) == 1 + threshold * (rounds + 1)
        stream = list(reversed(witness))
        assert len(stream) == threshold * (3 + rounds)
        remaining, selection = list(range(pool['n'])), []
        for slot in range(threshold):
            tau, hint = stream[2*slot:2*slot+2]
            depth = int.from_bytes(hint, 'little')
            assert 1 <= depth <= len(remaining)
            label = remaining.pop(len(remaining) - depth)
            assert hash160(tau) == table[label]
            selection.append((label, tau))
        assert [label for label, _ in selection] == pool['selected']
        digits.append(rank_subset(pool['selected'], pool['n']))
        for slot, (label, tau) in enumerate(reversed(selection)):
            key = decode_key(stream[2*threshold+rounds*threshold+slot])
            target = decode_key(bytes.fromhex(pool['targets'][label]))
            rt, st, flag = unpack_signature(tau)
            assert len(tau) == 40 and st == flag == 1 and rt == target[0]
            z0 = int.from_bytes(digest(spend, index, contexts[1+slot], flag), 'big') % N
            key_index = len(keys)
            keys.append(key)
            rows.append((key_index, rt, st, z0))
            targets.append((target, rt, z0, pool['pool'], label))
            for j in range(rounds):
                sigma = stream[2*threshold+j*threshold+slot]
                assert len(sigma) == 60
                r, s, flag = unpack_signature(sigma)
                z = int.from_bytes(digest(spend, index, contexts[1+threshold+j*threshold+slot], flag), 'big') % N
                rows.append((key_index, r, s, z))
    print(f'Validated contexts for {len(keys)} labels; solving {len(rows)} public ECDSA rows', flush=True)
    result = analyze_publication(keys, rows)
    assert all(scalar is not None for scalar in result['key_scalars'])
    recovered = []
    for secret, (target, rt, z0, pool_index, label) in zip(result['key_scalars'], targets):
        candidate = (rt * secret + z0) % N
        choices = [t for t in (candidate, -candidate % N) if mul(t) == target]
        assert len(choices) == 1
        recovered.append(dict(pool=pool_index, label=label, scalar=f'{choices[0]:064x}', target=encode_key(target).hex()))
    assert recovered == historical['recovery']['extractions']
    rank = 0
    for digit in reversed(digits):
        rank = rank * built['radix'] + digit
    assert rank < 1 << 2048
    payload = rank.to_bytes(256, 'big')
    assert payload.hex() == built['payload_hex']
    paths = [Path(__file__), HERE/'cross_key_nonce_extraction.py', HERE/'nonce_relation_extraction.py',
             HERE/'core_check.py', HERE/'publication_core_check.py', HERE/'anchored_native_core_check.py',
             HERE/'windowed_native_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    return dict(evidence='locally-reproduced', deployment='unclassified',
        scope=__doc__, general_extraction_proved=False, new_core_validation=False,
        extracted_target_scalars=len(recovered), signature_rows=len(rows),
        authorization_equations_checked=built['pool_count'],
        nonce_orbits=result['nonce_orbits'], components=result['components'],
        payload_sha256=hashlib.sha256(payload).hexdigest(), combined_vbytes=funding['vsize']+spend['vsize'],
        historical_native_evidence=historical['evidence'],
        historical_native_deployment=historical['deployment_class'],
        incremental_script_bytes=0, incremental_witness_bytes=0, incremental_hint_items=0,
        per_pool_hint_items=5, per_pool_entry_items=46, per_pool_complete_witness_items=47,
        total_hint_items=475, total_entry_items=4370, total_pool_witness_items=4465,
        per_pool_combined_stack_peak=100,
        bitcoin_tx_binary=str(binary), bitcoin_tx_sha256=sha(binary),
        bitcoin_tx_version=subprocess.run([str(binary), '-version'], capture_output=True, text=True, check=True).stdout.strip(),
        native_artifact_sha256=sha(artifact), historical_report_sha256=sha(historical_path),
        source_sha256={str(path.relative_to(ROOT)):sha(path) for path in paths})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-tx', type=Path, default=Path('/private/tmp/pointlock-bitcoin-tx-30.3'))
    args = parser.parse_args()
    report = replay(args.bitcoin_tx)
    (HERE/'cross-key-native-replay.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f'PASS {report["extracted_target_scalars"]} target scalars; {report["combined_vbytes"]} unchanged vB')
