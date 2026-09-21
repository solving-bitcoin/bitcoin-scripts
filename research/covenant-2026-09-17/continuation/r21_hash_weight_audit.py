#!/usr/bin/env python3
"""Independent closed-form audit of R21's fixed-translation color game.

Reads saved data only, imports none of the construction or dynamic program.
"""
import hashlib
import json
import math
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent

def fraction(row):
    return Fraction(int(row['numerator']), int(row['denominator']))

def main():
    path = HERE / 'r21_hash_weight_cost.json'
    data = json.loads(path.read_text())
    checked = []
    for game in data['finite_games']:
        size, colors, budget = game['vertices'], int(game['uniform_colors']), game['query_cap']
        if budget <= 1:
            expected, rule = Fraction(0), 'at most one queried vertex'
        elif budget == 2:
            expected, rule = Fraction(1, colors), 'query an adjacent pair'
        elif budget == 3 and size >= 5:
            expected, rule = Fraction(2 * colors - 1, colors**2), 'triangle-free three-query optimum'
        elif budget == size:
            expected = 1 - Fraction((colors - 1)**size + (-1)**size * (colors - 1), colors**size)
            rule = 'cycle chromatic polynomial'
        else:
            continue
        assert fraction(game['optimal_adaptive_success']) == expected
        checked.append({'vertices': size, 'colors': str(colors), 'query_cap': budget,
                        'rule': rule, 'probability': str(expected)})
    assert len(checked) == 65
    assert data['fully_enumerated_hash_functions'] == sum(c**n for n in (3, 5) for c in (2, 3, 4)) == 1398
    raw = data['ideal_SHA256_reduction']
    order = int(raw['order_n'])
    # Exactly slack residues have two 256-bit preimages; the rest have one.
    slack = 2**256 - order
    assert 0 < slack < order
    assert int(raw['double_preimage_scalars']) == slack
    assert fraction(raw['maximum_color_mass']) == Fraction(2, 2**256)
    assert fraction(raw['independent_pair_equality_probability']) == Fraction(4*slack + (order-slack), 2**512)
    assert int(raw['query_cap']) == 2**64
    assert fraction(raw['fixed_source_success_upper_bound']) == Fraction(1, 2**190)
    assert fraction(raw['fixed_2pow32_source_catalogue_upper_bound']) == Fraction(1, 2**158)
    assert fraction(data['ideal_160bit']['fixed_source_success_upper_bound']) == Fraction(1, 2**95)
    cap = int(raw['query_cap'])
    assert fraction(raw['arbitrary_source_u_zero_collision_bound']) == Fraction(cap*(cap-1), 2**256) < Fraction(1, 2**128)
    assert fraction(data['ideal_160bit']['arbitrary_source_u_zero_collision_bound']) == Fraction(cap*(cap-1), 2**161) < Fraction(1, 2**33)
    post = data['post_query_source_selection_control']
    colors, queries = post['colors'], post['distinct_vertex_queries']
    assert queries <= post['vertices'] and queries <= colors
    # Count injective color assignments by a falling factorial, rather than
    # reusing the source's iterative conditional-probability calculation.
    injective = math.factorial(colors) // math.factorial(colors-queries)
    birthday = 1-Fraction(injective, colors**queries)
    assert fraction(post['any_repeated_color_probability']) == birthday
    assert birthday > fraction(post['inapplicable_fixed_source_bound']) == Fraction(2*queries, colors)
    for game in data['fixed_catalogue_games']:
        size, shifts = game['vertices'], game['fixed_shifts']
        # Explicit neighbor construction, independent of the code's set formula.
        edges = {tuple(sorted((vertex, (vertex+shift) % size)))
                 for vertex in range(size) for shift in shifts}
        degrees = [sum(vertex in edge for edge in edges) for vertex in range(size)]
        assert max(degrees) == game['graph_degree'] <= 2*len(shifts)
        assert fraction(game['optimal_success']) <= min(Fraction(1), Fraction(max(degrees)*game['query_cap'], game['colors']))
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': 'Independent closed-form saved-data audit; no imported dynamic program or new native execution.',
              'audited_JSON_SHA256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'closed_form_cases': checked, 'closed_form_case_count': len(checked),
              'exact_modulo_color_mass_and_probability_checks': True,
              'postselection_counterexample_and_general_collision_bounds_checked': True,
              'catalogue_explicit_graph_checks': len(data['fixed_catalogue_games']),
              'all_assertions_passed': True}
    (HERE / 'r21_hash_weight_audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'closed_form_cases': len(checked), 'catalogue_graphs': len(data['fixed_catalogue_games'])}))

if __name__ == '__main__':
    main()
