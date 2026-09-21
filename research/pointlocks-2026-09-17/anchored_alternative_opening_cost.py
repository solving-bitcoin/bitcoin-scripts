#!/usr/bin/env python3
"""Cost model for a concrete alternative-nonce strategy, NOT a lower bound.

No point search, signing grind or non-extracting native spend is executed.
The model assumes uniform nonce x-coordinates and random-oracle-like fresh
native digests, with the disclosed rare-event independence approximation.
"""
import json
import math
from pathlib import Path

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def interval(length):
    # Exact positive DER integer length, including possible sign-padding byte.
    return (1 if length == 1 else 1 << (8*(length-1)-1), 1 << (8*length-1))


def estimate(rounds, rbytes, per_round, flags):
    slo, shi = interval(53-rbytes)
    rlo, rhi = interval(rbytes)
    probability_r = (rhi-rlo)/P
    probability_s = 2*(shi-slo)/N  # Either s or n-s normalizes to low-S.
    trials_per_round = per_round*flags
    probability_round = -math.expm1(trials_per_round*math.log1p(-probability_s))
    log_transactions = -rounds*math.log2(probability_round)
    return dict(rounds=rounds, r_der_bytes=rbytes, s_der_bytes=53-rbytes,
                distinct_nonce_count=rounds*per_round, nonces_per_round=per_round,
                flags_per_context=flags,
                log2_nonce_point_trials=math.log2(rounds*per_round/probability_r),
                log2_transaction_trials=log_transactions,
                log2_scalar_signature_checks=log_transactions+math.log2(rounds*trials_per_round),
                per_signature_success_probability=probability_s)


def main():
    rows = []
    for rounds in range(3,17):
        for flags in (1, 6, 256):
            choices = [estimate(rounds, width, q, flags)
                       for width in range(22, 31)
                       for q in sorted(set(range(1, 17)) | {1 << j for j in range(5, 41)})]
            # Screening only: group point trials and scalar checks are different
            # operations. Never reinterpret this maximum as bits of security.
            best = min(choices, key=lambda r: max(r['log2_nonce_point_trials'], r['log2_scalar_signature_checks']))
            rows.append(best)
    report = dict(evidence='inspected', deployment='unclassified',
                  scope=__doc__, no_attack_search_executed=True,
                  warning='This is a heuristic cost estimate for an explicit attack strategy, not a proven lower bound or a cryptographic security claim. Units are deliberately separate.',
                  five_round_simple_strategy=estimate(5, 23, 1, 6), scan=rows)
    path = Path(__file__).with_suffix('.json')
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['five_round_simple_strategy'], indent=2))


if __name__ == '__main__':
    main()
