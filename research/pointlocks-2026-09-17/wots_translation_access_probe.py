#!/usr/bin/env python3
"""Focused reproduction of the WOTS translation interface in ePrint2026/1684.

Tests access counts, polynomial reconstruction, and the separate malicious-table
binding obligation. No Bitcoin execution, point lock, setup benchmark, or full
garbling privacy proof is claimed. All test seeds are public deterministic data.
"""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIELD = (1 << 127)-1  # Test sharing field, not a proposed secp256k1 label domain.


def h160(value):
    return hashlib.new('ripemd160', hashlib.sha256(value).digest()).digest()


def prf(seed, domain):
    return int.from_bytes(hashlib.sha256(domain+seed).digest(), 'big') % FIELD


def chain(seed, length):
    out = [seed]
    for _ in range(length):
        out.append(h160(out[-1]))
    return out


def eval_poly(coefficients, x):
    y = 0
    for c in reversed(coefficients):
        y = (y*x+c) % FIELD
    return y


def interpolate_zero(points):
    assert len({x for x, _ in points}) == len(points) and all(x for x, _ in points)
    answer = 0
    for x, y in points:
        top, bottom = 1, 1
        for xx, _ in points:
            if xx != x:
                top = top*(-xx) % FIELD
                bottom = bottom*(x-xx) % FIELD
        answer = (answer+y*top*pow(bottom, -1, FIELD)) % FIELD
    return answer


def poly_domain(i, bit, side):
    return f'bitcoin-lab/wots-translation/v1/{i}/{bit}/{side}/'.encode()


def coefficient(seed, domain):
    return prf(seed, domain+b'coefficient/')


def mask(seed, domain, x):
    return prf(seed, domain+b'point/'+x.to_bytes(4, 'big'))


def setup(digits, width):
    k, maximum = (1 << width)-1, digits*((1 << width)-1)
    streams = [chain(hashlib.sha256(f'wots-translation-data-{i}'.encode()).digest()[:20], k)
               for i in range(digits)]
    checksum = chain(hashlib.sha256(b'wots-translation-checksum').digest()[:20], maximum)
    public = dict(digits=digits, width=width, endpoints=[v[-1] for v in streams],
                  checksum_endpoint=checksum[-1], polynomials=[])
    expected = {}
    for i, bit, side in itertools.product(range(digits), range(width), range(2)):
        domain = poly_domain(i, bit, side)
        selected = [int(((v >> bit) & 1) == side) for v in range(k+1)]
        shift = 1-selected[k]
        helper = [selected[v]-selected[v+1]+1 for v in range(k)]
        # For shift=0 the constant itself is chain-derived. For shift=1,
        # coefficient index -1 is undefined: retain an independent constant.
        coeff = [prf(b'public-fixture-label', domain)] if shift else []
        coeff += [coefficient(checksum[j], domain) for j in range(maximum)]
        assert len(coeff) == maximum+shift
        rows = []
        for owner in range(digits):
            for state in range(k):
                for _ in range(helper[state] if owner == i else 1):
                    x = len(rows)+1
                    cipher = (eval_poly(coeff, x)+mask(streams[owner][state], domain, x)) % FIELD
                    rows.append(dict(owner=owner, state=state, x=x, cipher=cipher))
        public['polynomials'].append(dict(i=i, bit=bit, side=side, shift=shift, rows=rows,
            label_hash=hashlib.sha256(coeff[0].to_bytes(16, 'big')).hexdigest()))
        expected[i, bit, side] = coeff[0]
    return public, dict(streams=streams, checksum=checksum), expected


def sign(secret, message, width):
    k = (1 << width)-1
    weight = sum(k-v for v in message)
    return dict(message=list(message), states=[a[v] for a, v in zip(secret['streams'], message)],
                checksum=secret['checksum'][weight])


def verify_wots(public, signature):
    k, width = (1 << public['width'])-1, public['width']
    msg = signature['message']
    if len(msg) != public['digits'] or len(signature['states']) != len(msg):
        return False
    if not all(isinstance(v, int) and 0 <= v < (1 << width) for v in msg):
        return False
    weight = sum(k-v for v in msg)
    return (all(chain(y, k-v)[-1] == endpoint for y, v, endpoint in
                zip(signature['states'], msg, public['endpoints']))
            and chain(signature['checksum'], public['digits']*k-weight)[-1] == public['checksum_endpoint'])


def evaluate(public, signature):
    """Receives only public parameters/ciphertexts and one signature, never seeds."""
    assert verify_wots(public, signature)
    k, msg = (1 << public['width'])-1, signature['message']
    maximum, weight = public['digits']*k, sum(k-v for v in msg)
    accessible = [{j+v: x for j, x in enumerate(chain(y, k-v))}
                  for y, v in zip(signature['states'], msg)]
    checksum = {j+weight: x for j, x in enumerate(chain(signature['checksum'], maximum-weight))}
    recovered = {}
    deficits = []
    for poly in public['polynomials']:
        domain = poly_domain(poly['i'], poly['bit'], poly['side'])
        shift = poly['shift']
        threshold = weight+shift
        high = [0]*threshold + [coefficient(checksum[m-shift], domain)
                               for m in range(threshold, maximum+shift)]
        points = []
        for row in poly['rows']:
            if row['state'] in accessible[row['owner']]:
                y = (row['cipher']-mask(accessible[row['owner']][row['state']], domain, row['x'])
                     -eval_poly(high, row['x'])) % FIELD
                points.append((row['x'], y))
        deficit = threshold-len(points)
        assert deficit in (0, 1)
        deficits.append(deficit)
        if deficit == 0:
            label = interpolate_zero(points) if threshold else high[0]
            identifier = (poly['i'], poly['bit'], poly['side'])
            recovered[identifier] = dict(label=label,
                matches_commitment=hashlib.sha256(label.to_bytes(16, 'big')).hexdigest() == poly['label_hash'])
    return recovered, deficits


def access_counts(digits, width):
    k = (1 << width)-1
    checked = 0
    for msg in itertools.product(range(k+1), repeat=digits):
        weight = sum(k-v for v in msg)
        for i, bit, side in itertools.product(range(digits), range(width), range(2)):
            selected = [int(((v >> bit) & 1) == side) for v in range(k+1)]
            shift = 1-selected[k]
            helper = [selected[v]-selected[v+1]+1 for v in range(k)]
            available = weight-(k-msg[i])+sum(helper[msg[i]:])
            assert weight+shift-available == 1-selected[msg[i]]
            checked += 1
    return checked


def main():
    profiles = [(8, 1), (4, 2), (2, 3), (2, 4)]
    counts = [dict(digits=n, width=d, messages=1 << (n*d),
                   label_deficit_checks=access_counts(n, d)) for n, d in profiles]
    public, secret, expected = setup(2, 2)
    messages, labels = 0, 0
    for msg in itertools.product(range(4), repeat=2):
        sigma = sign(secret, msg, 2)
        opened, deficits = evaluate(public, sigma)
        assert len(opened) == 4 and deficits.count(0) == deficits.count(1) == 4
        for key, value in opened.items():
            assert value['label'] == expected[key] and value['matches_commitment']
            assert key[2] == (msg[key[0]] >> key[1]) & 1
        messages += 1; labels += len(opened)
    # Alter one accessible ciphertext while keeping every WOTS endpoint and
    # every intended label commitment. No chain collision or forgery is needed.
    sigma = sign(secret, (0, 0), 2)
    damaged = {**public, 'polynomials': [{**p, 'rows': [dict(r) for r in p['rows']]}
                                      for p in public['polynomials']]}
    target = next(p for p in damaged['polynomials'] if (p['i'], p['bit'], p['side']) == (0, 0, 0))
    target['rows'][0]['cipher'] = (target['rows'][0]['cipher']+1) % FIELD
    assert verify_wots(damaged, sigma)
    bad, _ = evaluate(damaged, sigma)
    assert bad[0, 0, 0]['label'] != expected[0, 0, 0]
    assert not bad[0, 0, 0]['matches_commitment']
    assert damaged['endpoints'] == public['endpoints']
    assert [p['label_hash'] for p in damaged['polynomials']] == [p['label_hash'] for p in public['polynomials']]
    report = dict(question=__doc__, evidence='locally-reproduced', deployment_class='unclassified',
        reference=dict(url='https://eprint.iacr.org/2026/1684.pdf',
            pdf_title_date='2026-07-27', pdf_pages=22,
            pdf_sha256='64911295ba6ffa3e3b23c8075bb074d8995e55f11d1b949c5f17a59e10124745'),
        field=FIELD, profiles=counts, reconstruction=dict(messages=messages, selected_labels=labels,
            ciphertext_rows=sum(len(p['rows']) for p in public['polynomials'])),
        full_message_row_counts=[dict(message_bits=2048, chunk_bits=b, digit_bits=4,
            chunks=2048//b, single_checksum_chains=2048//b,
            message_chains=512, ciphertext_rows=4096*(b//4)*15,
            field_ciphertext_payload_bytes=16*4096*(b//4)*15)
            for b in (4, 8, 128)],
        malformed_table=dict(wots_still_valid=True, endpoints_unchanged=True,
            intended_label_hashes_unchanged=True, selected_label_commitment_failed=True,
            scope='Missing public table-binding obligation; not an attack on honest-garbler privacy or the paper protocol with its own audit.'),
        bitcoin_execution=False, point_scalar_extraction=False, setup_benchmark=False,
        hint_items=None, stack_peak=None, script_bytes=None, witness_bytes=None,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), all_expectations_met=True)
    (HERE/'wots-translation-access-probe.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
