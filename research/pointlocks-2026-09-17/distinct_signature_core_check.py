#!/usr/bin/env python3
"""Native counterexample to amplifying exact60 checks by byte inequality alone.

This is a legacy SINGLE-constant diagnostic, not an attack on the anchored
P2WSH candidate. A transparent lifted nonce point is used without its scalar.
Core runs on fresh regtest with networking and wallets disabled.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import (BUG_DIGEST, Node, consensus_check, decode_key, instructions,
                        isolated_core_binary, native_digest, p2sh, push,
                        scalar_bytes, scalar_value, serialize_spend, transaction,
                        unpack_signature)
from publication_core_check import accept_and_mine, encode_key
from legacy_same_signature_counterexample import N, P, add, mul, verify
from anchored_extraction import HALF_R, der
from direct_context_extraction import extract

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FLAGS = [3 + 32*i for i in range(8)]
DOMAIN = b'bitcoin-lab/distinct-exact60/single-constant/v1'


def make_fixture():
    # 21-byte positive DER r, obtained by hashing then lifting x. Never use a
    # known scalar times G as the nonce-point generator in this counterexample.
    start = (1 << 160) + int.from_bytes(hashlib.sha256(DOMAIN).digest()[:20], 'big')
    for counter in range(1000):
        r = start + counter
        rhs = (r*r*r+7) % P
        y = pow(rhs, (P+1)//4, P)
        if y*y % P == rhs:
            nonce = (r, min(y, P-y))
            break
    else:
        raise AssertionError('deterministic point lift exhausted')
    c, s = int.from_bytes(BUG_DIGEST, 'big'), N//2
    key = mul(pow(r, -1, N), add(mul(s, nonce), mul(-c)))
    assert key is not None and r != HALF_R and P-N < r < N
    assert add(mul(r, key), mul(c)) == mul(s, nonce)
    sigs = {(ss, flag): der(r, ss)[:-1]+bytes([flag])
            for ss in (s, N-s) for flag in FLAGS}
    assert len(set(sigs.values())) == 16
    for (ss, flag), signature in sigs.items():
        assert len(signature) == 60
        assert unpack_signature(signature) == (r, ss, flag)
        valid, recovered = verify(c, r, ss, key)
        assert valid and recovered[0] == nonce[0]
    return dict(key=key, nonce=nonce, r=r, s=s, counter=counter, signatures=sigs)


def compile_scripts(fixture):
    result = subprocess.run(['cargo', 'run', '--locked', '--quiet', '--example',
                             'pointlock_distinct_signature_probe', '--',
                             encode_key(fixture['key']).hex()], cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def push_element(data):
    if len(data) <= 255:
        return push(data)
    assert len(data) <= 520
    return b'\x4d'+len(data).to_bytes(2, 'little')+data


def trace(script, entry, inputs, outputs):
    """Independent straight-line trace of the policy-compiled diagnostic only."""
    stack, alt = list(entry), []
    peak, ops, checks, failure = len(stack), 0, [], None
    for _, _, op, data in instructions(script):
        ops += op > 0x60
        if data is not None:
            stack.append(data)
        elif op == 0:
            stack.append(b'')
        elif 0x51 <= op <= 0x60:
            stack.append(scalar_bytes(op-0x50))
        elif op == 0x79:  # PICK
            index = scalar_value(stack.pop())
            assert 0 <= index < len(stack)
            stack.append(stack[-1-index])
        elif op == 0x76:
            stack.append(stack[-1])
        elif op == 0x6e:
            stack.extend(stack[-2:])
        elif op == 0x78:
            stack.append(stack[-2])
        elif op == 0x7c:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 0x82:
            stack.append(scalar_bytes(len(stack[-1])))
        elif op in (0x87, 0x88):
            same = stack.pop() == stack.pop()
            if op == 0x88:
                if not same:
                    failure = 'equalverify'; break
            else:
                stack.append(scalar_bytes(int(same)))
        elif op == 0x91:
            stack.append(scalar_bytes(int(scalar_value(stack.pop()) == 0)))
        elif op == 0xa1:
            right, left = scalar_value(stack.pop()), scalar_value(stack.pop())
            stack.append(scalar_bytes(int(left <= right)))
        elif op == 0x69:
            if scalar_value(stack.pop()) == 0:
                failure = 'verify'; break
        elif op == 0x6b:
            alt.append(stack.pop())
        elif op == 0x6c:
            stack.append(alt.pop())
        elif op == 0x75:
            stack.pop()
        elif op in (0xac, 0xad):
            key, signature = stack.pop(), stack.pop()
            digest, preimage, _ = native_digest(inputs, outputs, 1, script, signature)
            try:
                r, s, flag = unpack_signature(signature)
                accepted = verify(int.from_bytes(digest, 'big'), r, s, decode_key(key))[0]
            except (AssertionError, ValueError):
                accepted = False
            checks.append(dict(signature=signature.hex(), digest=digest.hex(),
                               single_constant=preimage is None, accepted=accepted))
            if op == 0xad:
                if not accepted:
                    failure = 'checksigverify'; break
            else:
                stack.append(scalar_bytes(int(accepted)))
        else:
            raise AssertionError(f'unsupported compiled opcode {op:02x}')
        peak = max(peak, len(stack)+len(alt))
    accepted = failure is None and len(stack) == 1 and stack[0] == b'\x01' and not alt
    return dict(accepted=accepted, failure=failure, combined_stack_peak=peak,
                executed_non_push_opcodes=ops, checks=checks)


def cases(fixture):
    s, sigs = fixture['s'], fixture['signatures']
    normal = [sigs[s, 3], sigs[s, 131]]
    mixed = [sigs[ss, flag] for flag in (3, 131, 35) for ss in (s, N-s)]
    duplicate = list(mixed)
    duplicate[4] = duplicate[0]  # Deliberately nonadjacent: test all-pairs binding.
    return [
        ('existing-max60-low-s', [sigs[s, 3]], True, True, False),
        ('existing-max60-high-s', [sigs[N-s, 3]], True, False, False),
        ('two-standard-flags', normal, True, True, False),
        ('two-s-signs', [sigs[s, 3], sigs[N-s, 3]], True, False, False),
        ('six-mixed-distinct', mixed, True, False, False),
        ('eight-low-s-distinct', [sigs[s, flag] for flag in FLAGS], True, False, False),
        ('eight-high-s-distinct', [sigs[N-s, flag] for flag in FLAGS], True, False, False),
        ('nonadjacent-duplicate', duplicate, False, False, False),
        ('wrong-scalar', [der(fixture['r'], s-1)[:-1]+b'\x03', normal[1]], False, False, False),
        ('wrong-length', [normal[0][:-2]+normal[0][-1:], normal[1]], False, False, False),
        ('wrong-flag-all', [normal[0][:-1]+b'\x01', normal[1]], False, False, False),
        ('in-range-single', normal, False, False, True),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--algebra-only', action='store_true')
    args = parser.parse_args()
    fixture = make_fixture()
    compiled = compile_scripts(fixture)
    scripts = {row['count']: bytes.fromhex(row['script_hex']) for row in compiled['rows']}
    # Initial smoke test before starting Core, with a synthetic outpoint but the
    # actual legacy constant-digest branch. This is not native funding evidence.
    for name, sigs, expected, _, in_range in cases(fixture):
        script = scripts[len(sigs)]
        inputs = [('11'*32, 0, b'', 0xffffffff), ('11'*32, 1, b'', 0xffffffff)]
        outputs = [(1000, b'\x51')]*(2 if in_range else 1)
        outcome = trace(script, sigs, inputs, outputs)
        assert outcome['accepted'] == expected, (name, outcome)
    print('PASS algebra: 16 distinct exact60 signatures, one r and one digest; 12 predicate controls', flush=True)
    if args.algebra_only:
        print(json.dumps(compiled, indent=2))
        return
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = dict(scope=__doc__, bitcoin_core=provenance, compilation=compiled,
                  evidence='differentially-validated', deployment_class='consensus-validated',
                  p2wsh_attack=False, hint_items_per_predicate=0, results=[],
                  algebra=dict(domain=DOMAIN.decode(), lift_counter=fixture['counter'],
                      nonce_point=encode_key(fixture['nonce']).hex(),
                      committed_key=encode_key(fixture['key']).hex(),
                      r=f"{fixture['r']:064x}", s=f"{fixture['s']:064x}",
                      other_s=f"{N-fixture['s']:064x}", flags=FLAGS,
                      signatures=[sig.hex() for sig in fixture['signatures'].values()],
                      distinct_signature_bytes=16, distinct_r=1, distinct_digest=1,
                      private_key_or_nonce_scalar_used=False))
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-distinct60-') as temporary:
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
            fund = transaction(coinbase['txid'], coin['n'], [b'\x51'],
                               [(100_000, mining)] + [(100_000, p2sh(scripts[n])) for n in (1, 2, 6, 8)]
                               + [(5_000_000_000-510_000, mining)])
            funding, report['test_fixture_funding'] = accept_and_mine(node, address, fund['hex'])
            for name, sigs, expected, policy_expected, in_range in cases(fixture):
                script = scripts[len(sigs)]
                script_sig = b''.join(push_element(sig) for sig in sigs)+push_element(script)
                inputs = [(funding['txid'], 0, b'', 0xffffffff),
                          (funding['txid'], {1: 1, 2: 2, 6: 3, 8: 4}[len(sigs)], script_sig, 0xffffffff)]
                outputs = [(90_000, mining), (90_000, mining)] if in_range else [(190_000, mining)]
                spend = serialize_spend(inputs, outputs, 0)
                spend['vsize'] = (spend['weight']+3)//4
                decoded = node.rpc('decoderawtransaction', spend['hex'])
                for key in ('txid', 'weight', 'vsize'):
                    assert decoded[key] == spend[key]
                assert decoded['hash'] == spend['wtxid'] and decoded['size'] == spend['total_bytes']
                outcome = trace(script, sigs, inputs, outputs)
                assert outcome['accepted'] == expected
                found = None
                if expected:
                    assert len(set(sigs)) == len(sigs)
                    checks = [(bytes.fromhex(v['signature']), bytes.fromhex(v['digest'])) for v in outcome['checks']]
                    assert len(checks) == len(sigs) and {v[1] for v in checks} == {BUG_DIGEST}
                    found = extract(encode_key(fixture['key']), checks)
                    assert found is None
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                assert policy['allowed'] == policy_expected, (name, policy)
                report['results'].append(dict(name=name, expected=expected,
                    policy=policy, transaction=spend, trace=outcome,
                    known_or_repeated_nonce_extractor=found,
                    script_sig_bytes=len(script_sig), redeem_entry_items=len(sigs),
                    script_sig_push_items=len(sigs)+1, incremental_hint_items=0,
                    complete_transaction_serialized_witness_bytes=spend['witness_bytes'],
                    predicate_witness_item_count=0,
                    predicate_witness_serialization_bytes=1))
            # Evaluate policy before mining competing spends, so block resets
            # cannot cause mempool-conflict rejections in place of script policy.
            base_height = node.rpc('getblockcount')
            for row in report['results']:
                result = consensus_check(node, address, row['transaction'])
                assert result['accepted'] == row['expected'], (row['name'], result)
                row['consensus'] = result
                row['deployment_class'] = ('policy-validated' if row['policy']['allowed'] else
                    'consensus-validated' if result['accepted'] else 'consensus-incompatible')
                if result['accepted']:
                    node.rpc('invalidateblock', result['block_hash'])
                assert node.rpc('getblockcount') == base_height
                print(f"PASS {row['name']}: Core consensus={result['accepted']}, policy={row['policy']['allowed']}", flush=True)
        finally:
            node.close()
    paths = [Path(__file__), ROOT/'examples/pointlock_distinct_signature_probe.rs',
             ROOT/'src/signatures/pointlocks/mod.rs',
             HERE/'core_check.py', HERE/'direct_context_extraction.py',
             HERE/'anchored_extraction.py', HERE/'publication_core_check.py',
             ROOT/'research/covenant-2026-09-17/legacy_same_signature_counterexample.py',
             ROOT/'research/covenant-2026-09-17/core_gate_check.py',
             ROOT/'tools/core_regtest.py', ROOT/'tools/bitcoin_core_release.json',
             ROOT/'Cargo.lock']
    report['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report['all_expectations_met'] = True
    (HERE/'distinct-signature-core-check.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
