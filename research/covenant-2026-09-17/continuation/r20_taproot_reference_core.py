#!/usr/bin/env python3
"""Fund and independently Core-check the R20 mixed-input boundary fixture.

Raw consensus-boundary transactions, not library primitive measurements.
Fresh isolated regtest only; public fixture keys; no wallet or peers.
"""
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import r20_taproot_reference as host
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary
from core_regtest import Node, consensus_check, transaction


def main():
    alpha0, alpha1 = host.alpha(1), host.alpha(2)
    secret = 7
    public = host.b32(host.mul(secret)[0])
    leaf = host.push(alpha0) + b'\x88' + host.push(public) + b'\xac'
    commitment = host.commitment(host.point(b'\x02' + host.b32(host.NUMS_X)), leaf)
    auxiliary = host.tail(1)
    spent_all = [(900000, commitment['script_pubkey']),
                 (50000, host.p2sh(auxiliary)), (50000, b'\x51')]
    report = {'question': 'Does DEFAULT bind the exact auxiliary program and its actual witness row?',
              'scope': 'Funded mixed Taproot/P2SH raw boundary fixtures; no covenant or new PoW witness.',
              'main_leaf': leaf.hex(), 'auxiliary_redeem_script': auxiliary.hex(),
              'main_internal_key': f'{host.NUMS_X:064x}', 'public_leaf_signing_scalar': secret,
              'results': []}
    # Copy the pinned archive into a private cache: another task may be using
    # the common cached executable, which must not be replaced while running.
    with tempfile.TemporaryDirectory(prefix='covenant-r20-core-') as directory:
        root = Path(directory)
        cache = root / 'binary'
        cache.mkdir()
        for archive in Path('/private/tmp/covenant-core-30.3').glob('bitcoin-30.3-*.tar.gz'):
            shutil.copyfile(archive, cache / archive.name)
        binary, provenance = isolated_core_binary(cache, False)
        report['bitcoin_core'] = provenance
        chain = root / 'chain'
        chain.mkdir()
        node = Node(binary, chain)
        try:
            node.ready()
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(o for o in coinbase['vout'] if o['scriptPubKey']['hex'] == mining.hex())
            funding = transaction(coinbase['txid'], coin['n'], [b'\x51'],
                                  spent_all + [(4998990000, mining)])
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding
            txid_wire = bytes.fromhex(funding['txid'])[::-1]
            outpoint = lambda i: txid_wire + struct.pack('<I', i)
            inputs = [(outpoint(0), 0xffffffff), (outpoint(1), 0xffffffff)]
            outputs = [(940000, b'\x00\x14' + b'\x11' * 20)]
            message, preimage = host.default_sighash(inputs, outputs, spent_all[:2], 0, leaf)
            signature = host.schnorr_sign(secret, message, 11)
            assert host.schnorr_verify(signature, public, message)
            row0 = host.recovery_row(alpha0, 1 << 248)
            row1 = host.recovery_row(alpha1, 1 << 248)
            report['same_DEFAULT_signature'] = signature.hex()
            report['DEFAULT_message'] = message.hex()
            report['DEFAULT_preimage'] = preimage.hex()
            cases = []

            def build(name, tx_inputs, tx_outputs, prevouts, sig, claim, row,
                      expected, expected_policy):
                witness = [sig, claim, leaf, commitment['control']]
                script_sig = b'' if row is None else b''.join(host.push(x) for x in row + [auxiliary])
                scripts = [b''] + ([script_sig] if len(tx_inputs) == 2 else [])
                witnesses = [witness] + ([[]] if len(tx_inputs) == 2 else [])
                raw = host.serial(tx_inputs, tx_outputs, scripts, witnesses)
                shown = host.show(raw)
                tx = {'hex': shown['transaction_hex'], **{k: v for k, v in shown.items() if k != 'transaction_hex'}}
                actual_message, _ = host.default_sighash(tx_inputs, tx_outputs, prevouts, 0, leaf)
                schnorr_ok = host.schnorr_verify(sig, public, actual_message)
                auxiliary_ok = True
                if row is not None:
                    def native(s, key, suffix):
                        r, scalar_s = host.unpack_der(s)
                        assert s[-1] == 3
                        assert host.legacy_preimage(tx_inputs, tx_outputs, 1, suffix, 3) is None
                        return host.verify(1 << 248, r, scalar_s, host.point(key))[0]
                    try:
                        stack, alt, _ = host.execute(auxiliary, row, mock_check=native)
                        auxiliary_ok = stack == [b'\x01'] and not alt
                    except ValueError:
                        auxiliary_ok = False
                host_accept = schnorr_ok and claim == alpha0 and auxiliary_ok
                assert host_accept == expected, name
                main_witness_bytes = len(host.compact(4) + b''.join(host.vec(x) for x in witness))
                metrics = {
                    'boundary': 'complete-transaction: all input pushes, scripts, witnesses and output included; raw consensus-boundary bytecode, not compiler-policy library metrics',
                    'main_locking_program_bytes': len(commitment['script_pubkey']),
                    'main_leaf_bytes': len(leaf), 'main_control_bytes': len(commitment['control']),
                    'main_data_items': 2, 'main_hint_items': 0, 'main_full_witness_items': 4,
                    'main_serialized_witness_bytes': main_witness_bytes,
                    'main_combined_stack_peak_by_inspection_if_success': 3 if expected else None,
                    'main_static_non_push_opcodes': 2,
                    'main_executed_non_push_opcodes_if_success': 2 if expected else None,
                    'main_validation_budget_initial': 50 + main_witness_bytes,
                    'main_validation_budget_consumed_if_success': 50 if expected else None,
                    'auxiliary_input_present': len(tx_inputs) == 2,
                    'auxiliary_is_P2SH_checker': row is not None,
                    'auxiliary_locking_script_bytes': len(prevouts[1][1]) if len(prevouts) == 2 else 0,
                    'auxiliary_redeem_script_bytes': len(auxiliary) if row is not None else 0,
                    'auxiliary_data_items': len(row) if row is not None else 0,
                    'auxiliary_hint_items': 0, 'auxiliary_serialized_witness_bytes': 1 if len(tx_inputs) == 2 else 0,
                    'auxiliary_witness_items': 0,
                    'auxiliary_script_sig_bytes': len(script_sig),
                    'auxiliary_script_sig_push_items': len(row) + 1 if row is not None else 0,
                    'auxiliary_combined_stack_peak_by_inspection_if_success': (6 if row is not None else 1) if expected and len(tx_inputs) == 2 else None,
                    'auxiliary_redeem_only_stack_peak_by_inspection_if_success': 5 if expected and row is not None else None,
                    'auxiliary_redeem_static_non_push_opcodes': 9 if row is not None else 0,
                    'auxiliary_redeem_executed_non_push_opcodes_if_success': 9 if expected and row is not None else None,
                    'auxiliary_P2SH_additional_non_push_opcodes_if_success': 2 if expected and row is not None else 0,
                    'total_data_items': 2 + (len(row) if row is not None else 0),
                    'total_hint_items': 0,
                    'stack_composition': ('Separate input executions: main data at Tapscript entry; four auxiliary data at redeemScript entry after five scriptSig pushes. Zero hints throughout; no stack crosses inputs.' if row is not None else
                                          'Main data at Tapscript entry; replacement OP_TRUE starts with an empty separate stack. Zero hints throughout.' if len(tx_inputs) == 2 else
                                          'Main data at Tapscript entry; no auxiliary input; zero hints.'),
                    'witness_bytes_exclude_marker_flag': raw['witness_bytes'],
                    'marker_flag_bytes': 2,
                }
                cases.append({'name': name, 'transaction': tx, 'expected': expected,
                              'expected_policy': expected_policy, 'host_accept': host_accept,
                              'actual_DEFAULT_message': actual_message.hex(),
                              'DEFAULT_signature': sig.hex(), 'main_claimed_alpha': claim.hex(),
                              'auxiliary_row': None if row is None else [x.hex() for x in row],
                              'metrics': metrics})

            build('same-auxiliary-row', inputs, outputs, spent_all[:2], signature, alpha0, row0, True, True)
            build('different-auxiliary-row-same-DEFAULT-signature', inputs, outputs, spent_all[:2], signature, alpha0, row1, True, True)
            build('changed-main-claim', inputs, outputs, spent_all[:2], signature, alpha1, row0, False, False)
            build('changed-auxiliary-alpha-with-old-keys', inputs, outputs, spent_all[:2], signature, alpha0, [alpha1] + row0[1:], False, False)
            replacement = [inputs[0], (outpoint(2), 0xffffffff)]
            replacement_spent = [spent_all[0], spent_all[2]]
            replaced_message, _ = host.default_sighash(replacement, outputs, replacement_spent, 0, leaf)
            build('OP_TRUE-helper-old-DEFAULT-signature', replacement, outputs, replacement_spent,
                  signature, alpha0, None, False, False)
            replacement_sig = host.schnorr_sign(secret, replaced_message, 19)
            build('OP_TRUE-helper-fresh-public-key-signature', replacement, outputs, replacement_spent,
                  replacement_sig, alpha0, None, True, False)
            # Omitting the helper requires reducing the output amount to keep
            # value conservation. This is an explicit altered-output fixture.
            solo_inputs, solo_outputs, solo_spent = inputs[:1], [(890000, outputs[0][1])], spent_all[:1]
            solo_message, _ = host.default_sighash(solo_inputs, solo_outputs, solo_spent, 0, leaf)
            build('helper-omitted-old-DEFAULT-signature', solo_inputs, solo_outputs, solo_spent,
                  signature, alpha0, None, False, False)
            solo_sig = host.schnorr_sign(secret, solo_message, 23)
            build('helper-omitted-fresh-public-key-signature', solo_inputs, solo_outputs, solo_spent,
                  solo_sig, alpha0, None, True, True)

            # Test policy before connecting any conflicting spend. Invalidated
            # positive blocks may put their transactions back into the mempool.
            for case in cases:
                decoded = node.rpc('decoderawtransaction', case['transaction']['hex'])
                assert decoded['txid'] == case['transaction']['txid']
                assert decoded['hash'] == case['transaction']['wtxid']
                assert decoded['weight'] == case['transaction']['weight']
                case['policy'] = node.rpc('testmempoolaccept', [case['transaction']['hex']])[0]
                assert case['policy']['allowed'] == case['expected_policy'], (case['name'], case['policy'])
            for case in cases:
                consensus = consensus_check(node, address, case['transaction'])
                assert consensus['accepted'] == case['expected'], (case['name'], consensus)
                case['consensus'] = consensus
                case['evidence'] = 'differentially-validated'
                case['deployment_class'] = (('policy-validated' if case['policy']['allowed'] else 'consensus-validated')
                                            if case['expected'] else 'consensus-incompatible')
                if consensus['accepted']:
                    node.rpc('invalidateblock', consensus['block_hash'])
                    case['validation_block_invalidated_for_same_outpoint_comparison'] = True
                print('PASS', case['name'], 'accepted=', consensus['accepted'], flush=True)
            assert cases[0]['DEFAULT_signature'] == cases[1]['DEFAULT_signature']
            assert cases[0]['actual_DEFAULT_message'] == cases[1]['actual_DEFAULT_message']
            assert cases[0]['transaction']['txid'] != cases[1]['transaction']['txid']
            report['results'] = cases
            report['all_expectations_met'] = True
        finally:
            node.close()
    destination = HERE / 'r20_taproot_reference_core.json'
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(destination)


if __name__ == '__main__':
    main()
