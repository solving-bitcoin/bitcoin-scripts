#!/usr/bin/env python3
"""Fixed-source canonical-pair hash weights and their paired-color search.

Host group identities and exact finite random-oracle games only. No Script,
chosen Bitcoin hash, native signing witness, Core execution or field tests.
"""
from fractions import Fraction
from functools import lru_cache
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r11_lookup_reference import P, N, G, add, mul, point, encoded


def color_success(state, shifts=(1,)):
    size = len(state)
    return any(state[i] >= 0 and state[i] == state[(i + shift) % size]
               for shift in shifts for i in range(size))


def canonical(state):
    names = {}
    return tuple(-1 if c < 0 else names.setdefault(c, len(names)) for c in state)


def optimum(size, colors, shifts=(1,), compress=True):
    """Exact adaptive query game, with the public graph fixed in advance.

    Color names are exchangeable. In compressed mode every exposed color
    has probability 1/colors, all unexposed colors form one weighted case.
    Full-color mode is an independent small-case recurrence without that
    compression. Vertex choice still ranges over every unqueried vertex.
    """
    @lru_cache(None)
    def solve(state, remaining):
        if color_success(state, shifts):
            return Fraction(1)
        if not remaining or all(c >= 0 for c in state):
            return Fraction(0)
        known = max(state) + 1
        outcomes = ([(c, 1) for c in range(known)] +
                    ([(known, colors - known)] if known < colors else [])) if compress else [(c, 1) for c in range(colors)]
        best = Fraction(0)
        for vertex, current in enumerate(state):
            if current >= 0:
                continue
            value = Fraction(0)
            for new_color, multiplicity in outcomes:
                new_state = state[:vertex] + (new_color,) + state[vertex+1:]
                if compress:
                    new_state = canonical(new_state)
                value += multiplicity * solve(new_state, remaining - 1)
            best = max(best, value / colors)
        return best
    return solve


def fraction_json(x):
    return {'numerator': str(x.numerator), 'denominator': str(x.denominator),
            'log2_probability': None if not x else math.log2(x.numerator) - math.log2(x.denominator)}


def group_checks():
    # Fixed literal source r=s=1 has exactly the two roots +/-lift(1).
    R = point(b'\x02' + (1).to_bytes(32, 'big'))
    try:
        point(b'\x02' + (N + 1).to_bytes(32, 'big'))
    except ValueError:
        pass
    else:
        raise AssertionError('unexpected r+n branch')
    D = mul(2, R)
    values = [0, 1, 2, 1 << 248, N - 1]
    values += [int.from_bytes(hashlib.sha256(('r21-z-%d' % i).encode()).digest(), 'big') % N for i in range(7)]
    rows = []
    for z in values:
        plus, minus = add(R, mul(-z)), add(mul(-1, R), mul(-z))
        assert plus is not None and minus is not None and plus != minus
        assert add(plus, mul(-1, minus)) == D
        a = int.from_bytes(hashlib.sha256(encoded(plus)).digest(), 'big') % N
        b = int.from_bytes(hashlib.sha256(encoded(minus)).digest(), 'big') % N
        result = add(mul(a, plus), mul(b, minus))
        u, v = (a-b) % N, (-(a+b)*z) % N
        assert u != 0 and result is not None
        assert result == add(mul(u, R), mul(v))
        # Full-point permutation invariance, not merely x-only invariance.
        assert result == add(mul(b, minus), mul(a, plus))
        rows.append({'z': str(z), 'P': encoded(plus).hex(), 'Q': encoded(minus).hex(),
                     'a': str(a), 'b': str(b), 'u': str(u), 'v': str(v),
                     'aggregate': encoded(result).hex(), 'permutation_invariant': True,
                     'unknown_point_coefficient_nonzero': True})
    assert len({row['aggregate'] for row in rows}) == len(rows)
    return {'fixed_source_r': 1, 'fixed_source_s': 1, 'R': encoded(R).hex(),
            'translation_D': encoded(D).hex(), 'vectors': rows,
            'native_transaction_claim': False, 'Schnorr_signer_supplied': False}


def main():
    games, cross_checks = [], 0
    for size in (3, 5, 7):
        for colors in (2, 3, 16, 256, 1 << 160):
            solve = optimum(size, colors)
            initial = (-1,) * size
            for budget in range(min(size, 5) + 1):
                value = solve(initial, budget)
                bound = min(Fraction(1), Fraction(2 * budget, colors))
                assert value <= bound
                games.append({'vertices': size, 'uniform_colors': str(colors), 'query_cap': budget,
                              'optimal_adaptive_success': fraction_json(value),
                              'degree_two_union_bound': fraction_json(bound)})
            if size <= 5 and colors <= 3:
                direct = optimum(size, colors, compress=False)
                for budget in range(size + 1):
                    assert direct(initial, budget) == solve(initial, budget)
                    cross_checks += 1
    # Full function enumeration independently checks the query-all result.
    full_functions = 0
    for size in (3, 5):
        for colors in (2, 3, 4):
            hits = 0
            for f in itertools.product(range(colors), repeat=size):
                hits += color_success(f)
                full_functions += 1
            value = optimum(size, colors)((-1,) * size, size)
            assert value == Fraction(hits, colors**size)
    # A fixed catalogue is a union of translation graphs, max degree 2M.
    catalogue = []
    for shifts in ((1,), (1, 2), (1, 2, 3)):
        size, colors = 7, 16
        solve = optimum(size, colors, shifts)
        degree = len({s % size for shift in shifts for s in (shift, -shift)})
        assert degree <= 2 * len(shifts)
        for budget in range(6):
            value = solve((-1,) * size, budget)
            bound = min(Fraction(1), Fraction(2 * len(shifts) * budget, colors))
            assert value <= bound
            catalogue.append({'fixed_shifts': list(shifts), 'vertices': size, 'colors': colors,
                              'query_cap': budget, 'graph_degree': degree,
                              'optimal_success': fraction_json(value), 'union_bound': fraction_json(bound)})
    slack = (1 << 256) - N
    exact_mod_n_collision = Fraction(N + 3 * slack, 1 << 512)
    cap = 1 << 64
    # If the source shift is selected after colors are exposed, any repeated
    # color at distinct queried vertices can define its edge. This is a
    # counterexample to extending the fixed-graph theorem, not a native spend.
    post_colors, post_queries, post_vertices = 256, 8, 11
    all_distinct = Fraction(1)
    for i in range(post_queries):
        all_distinct *= Fraction(post_colors-i, post_colors)
    post_success = 1-all_distinct
    incorrect_fixed_bound = Fraction(2*post_queries, post_colors)
    assert post_success > incorrect_fixed_bound
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': __doc__, 'group': group_checks(),
              'finite_games': games, 'full_color_recurrence_cross_checks': cross_checks,
              'fully_enumerated_hash_functions': full_functions, 'fixed_catalogue_games': catalogue,
              'ideal_SHA256_reduction': {'order_n': str(N), 'double_preimage_scalars': str(slack),
                  'maximum_color_mass': fraction_json(Fraction(2, 1 << 256)),
                  'independent_pair_equality_probability': fraction_json(exact_mod_n_collision),
                  'query_cap': str(cap),
                  'fixed_source_success_upper_bound': fraction_json(Fraction(4 * cap, 1 << 256)),
                  'fixed_2pow32_source_catalogue_upper_bound': fraction_json(Fraction(4 * cap * (1 << 32), 1 << 256)),
                  'arbitrary_source_u_zero_collision_bound': fraction_json(Fraction(cap*(cap-1), 1 << 256))},
              'ideal_160bit': {'query_cap': str(cap),
                  'fixed_source_success_upper_bound': fraction_json(Fraction(2 * cap, 1 << 160)),
                  'arbitrary_source_u_zero_collision_bound': fraction_json(Fraction(cap*(cap-1), 1 << 161))},
              'post_query_source_selection_control': {'vertices': post_vertices, 'colors': post_colors,
                  'distinct_vertex_queries': post_queries, 'any_repeated_color_probability': fraction_json(post_success),
                  'inapplicable_fixed_source_bound': fraction_json(incorrect_fixed_bound),
                  'not_a_native_transaction': True},
              'assumptions': ['Point hash is an ideal fresh-answer oracle.',
                  'Source signature or finite catalogue is fixed before point-hash queries, including setup queries.',
                  'Queried point encodings are canonical compressed encodings; infinity is excluded.',
                  'The target is u=0 for the specified hash-weight aggregate, not arbitrary Schnorr signing.',
                  'Post-hash source selection, variable source scalars and different nonlinear functions are outside the fixed-source bound.'],
              'all_assertions_passed': True}
    output = HERE / 'r21_hash_weight_cost.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'secp_group_vectors': len(report['group']['vectors']),
                      'finite_adaptive_games': len(games), 'full_color_cross_checks': cross_checks,
                      'complete_hash_functions': full_functions, 'catalogue_games': len(catalogue)}, indent=2))


if __name__ == '__main__':
    main()
