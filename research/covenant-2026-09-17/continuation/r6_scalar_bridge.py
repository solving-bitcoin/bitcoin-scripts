#!/usr/bin/env python3
"""Finite oracle experiment for the restricted R6 equality-graph bridge.

This is not a Bitcoin Script executor. The 2-bit hash is deliberately a toy;
no consensus validity, PoW witness, or real hash collision is claimed.
"""
import itertools
import json
import math
from pathlib import Path


G_X = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')


def template():
    # Entry: a, sigma, path_bit. path_bit is the sole control hint.
    # Hash path is SHA1(sigma) or SHA1(SHA1(sigma)).
    # The numeric round trip checks a's canonical <=4-byte ScriptNum encoding.
    return (b'\x6b'                 # TOALTSTACK
            b'\x82\x01\x40\x88' # SIZE 64 EQUALVERIFY
            b'\x76\x20' + G_X + b'\xad'  # DUP <Gx> CHECKSIGVERIFY
            b'\xa7\x6c\x63\xa7\x68'     # SHA1 FROMALTSTACK IF SHA1 ENDIF
            b'\x7c\x76\x76\x00\x93\x88' # SWAP DUP DUP 0 ADD EQUALVERIFY
            b'\xa7\x87')          # SHA1 EQUAL


def small_oracles():
    """Enumerate every function from six inputs to four outputs.

    Inputs 4 and 5 represent length-separated native/reference roots.
    Outputs 0..3 represent hash states. The adaptive third query is at H(4).
    Thus all three queried inputs are distinct for every oracle.
    """
    counts = {'oracles': 0, 'first_path_accepts': 0,
              'second_path_accepts': 0, 'either_path_accepts': 0,
              'both_paths_accept': 0, 'any_output_collision': 0,
              'false_first_merge_claims': 0}
    examples = {}
    for table in itertools.product(range(4), repeat=6):
        counts['oracles'] += 1
        native_first, reference = table[4], table[5]
        native_second = table[native_first]
        first = native_first == reference
        second = native_second == reference
        collision = len({native_first, reference, native_second}) < 3
        counts['first_path_accepts'] += first
        counts['second_path_accepts'] += second
        counts['either_path_accepts'] += first or second
        counts['both_paths_accept'] += first and second
        counts['any_output_collision'] += collision
        # This assertion is the first-merge implication, tested independently
        # of whether the *terminal* path comparison accepts.
        if (first or second) and not collision:
            counts['false_first_merge_claims'] += 1
        key = ('both' if first and second else 'first_only' if first
               else 'second_only' if second else 'neither')
        examples.setdefault(key, {'table': table,
                                  'query_inputs': [4, 5, native_first],
                                  'query_outputs': [native_first, reference, native_second]})
    assert counts['oracles'] == 4096
    assert counts['first_path_accepts'] == counts['second_path_accepts'] == 1024
    assert counts['either_path_accepts'] == 1792
    assert counts['both_paths_accept'] == 256
    assert counts['any_output_collision'] == 2560
    assert counts['false_first_merge_claims'] == 0
    counts['exact_probabilities'] = {
        'fixed_first_path': '1/4', 'fixed_second_path': '1/4',
        'either_path': '7/16', 'both_paths': '1/16',
        'any_output_collision': '5/8',
        'three_query_union_bound': '3/4'}
    counts['examples'] = examples
    return counts


def compact(n):
    assert n < 253
    return bytes([n])


def main():
    raw = template()
    assert len(raw) == 53
    # Exact serialization lengths for the template, not accepting witnesses.
    serialization = []
    for selector_bytes in (0, 1):
        item_lengths = [4, 64, selector_bytes, len(raw), 33]
        total = len(compact(len(item_lengths))) + sum(1+n for n in item_lengths)
        serialization.append({'path_bit_bytes': selector_bytes,
                              'item_lengths': item_lengths,
                              'serialized_witness_bytes': total})
    q = 2**64
    upper = q*(q-1) / 2**161
    result = {
        'question': 'Can equality-only unary native hash graphs bridge a native 64-byte Schnorr signature to an arithmetic scalar without constructing its 64-byte serialization?',
        'evidence': 'locally-reproduced',
        'deployment': 'unclassified',
        'scope': 'Host finite-oracle experiment and raw unexecuted matcher template; not a complete covenant.',
        'seed': 'none; all 4^6 oracle tables are enumerated',
        'finite_oracle': small_oracles(),
        'ideal_hash_graph_estimates': {
            'minimum_output_bits': 160,
            'total_charged_fresh_queries': str(q),
            'collision_union_bound': 'Q*(Q-1)/2^161',
            'success_upper_at_2_pow_64_queries': upper,
            'log2_success_upper': math.log2(upper),
            'necessary_queries_for_half_success_via_union_bound': 'Q*(Q-1) >= 2^160; approximately 2^80',
            'known_target_extension': 'add M*Q/2^160 for M independently fixed 160-bit targets; include target setup/audit in total work',
        },
        'raw_matcher_template': {
            'script_hex': raw.hex(),
            'locking_script_bytes': len(raw),
            'compiler': 'none; explicitly raw, unexecuted boundary template',
            'entry_operand_items': 2,
            'entry_control_hint_items': 1,
            'total_entry_data_items': 3,
            'complete_witness_items_single_leaf_control': 5,
            'combined_main_alt_peak_derived': 5,
            'signature_budget_used_if_successful': 50,
            'witness_serialization_for_max_4_byte_operand': serialization,
            'limitations': ['No real accepting witness was mined.',
                            'No arithmetic reference verifier is supplied.',
                            'R=G is not enforced by this template; permitting arbitrary nonce only enlarges the analyzed native family.',
                            'No consensus or policy execution was performed.'],
        },
    }
    out = Path(__file__).with_suffix('.json')
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'oracles': 4096,
                      'either_path_accepts': 1792,
                      'template_bytes': len(raw),
                      'status': 'all finite-model assertions passed'}))


if __name__ == '__main__':
    main()
