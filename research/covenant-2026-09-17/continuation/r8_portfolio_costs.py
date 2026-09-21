#!/usr/bin/env python3
"""Expected-cost audit for a fixed public nonce portfolio, not a covenant.

The large calculation is explicitly a Poisson/mean surrogate. Small cases
exhaust the actual finite type model and validate the Jensen distinction.
"""
from fractions import Fraction
from itertools import product
import json
import math
from pathlib import Path

from r7_nonce_portfolio import masses

HERE = Path(__file__).resolve().parent


def exhaustive():
    rows = []
    weights = (Fraction(1, 16), Fraction(1, 64))
    for count in (1, 2, 3, 4):
        sums = []
        actual = []
        for types in product(range(2), repeat=count):
            s = sum(weights[t] for t in types)
            union = 1 - math.prod(1 - weights[t] for t in types)
            sums.append(1 / s)
            actual.append(1 / union)
        jensen = Fraction(1, 1) / (count * sum(weights) / 2)
        conditional = sum(sums) / len(sums)
        actual_mean = sum(actual) / len(actual)
        assert jensen <= conditional <= actual_mean
        rows.append({"portfolio_rows": count, "type_assignments": 2**count,
                     "reciprocal_of_mean_pair_mass": str(jensen),
                     "mean_reciprocal_of_sum": str(conditional),
                     "mean_queries_independent_cell_model": str(actual_mean)})
    return rows


def conditional_query_surrogate(point_bits, minimum_width=24, intervals=2048):
    """Poissonize sparse widths; replace common contribution by its mean.

    Within this specified Poisson model, replacing the common contribution
    by its mean is optimistic by conditional Jensen. Poissonization is an
    approximation to the fixed-size width model, not a theorem about the curve.
    """
    points = 2.0 ** point_bits
    rare = []
    baseline = 0.0
    for width in range(minimum_width, 34):
        u, v = (float(x) for x in masses(width, 48-width))
        if width < 27:
            rare.append((points*u, v))
        else:
            baseline += points*u*v
    assert baseline > 0
    # E[1/S] = integral E[exp(-t*S)] dt; use u=t*baseline.
    # The normalized integrand is at most exp(-u), so truncation error <= e^-48.
    def integrand(u):
        return math.exp(-u + sum(lam*math.expm1(-u*v/baseline)
                                 for lam, v in rare))
    end = 48.0
    step = end/intervals
    value = integrand(0.0) + integrand(end)
    for index in range(1, intervals):
        value += (4 if index % 2 else 2)*integrand(index*step)
    return value*step/(3*baseline)


def optimize(point_cost, minimum_width):
    # Coarse sweep followed by a bounded golden-section refinement.
    def cost(bits):
        return point_cost*2.0**bits + conditional_query_surrogate(bits, minimum_width)
    grid = [58 + i/4 for i in range(41)]
    center = min(grid, key=cost)
    left, right = center-.3, center+.3
    ratio = (math.sqrt(5)-1)/2
    x1, x2 = right-ratio*(right-left), left+ratio*(right-left)
    f1, f2 = cost(x1), cost(x2)
    for _ in range(35):
        if f1 < f2:
            right, x2, f2 = x2, x1, f1
            x1 = right-ratio*(right-left)
            f1 = cost(x1)
        else:
            left, x1, f1 = x1, x2, f2
            x2 = left+ratio*(right-left)
            f2 = cost(x2)
    best = (left+right)/2
    q1 = conditional_query_surrogate(best, minimum_width)
    q2 = conditional_query_surrogate(best, minimum_width, intervals=8192)
    # Independent quadrature resolution, not a formal rounding-error bound.
    assert abs(q1/q2-1) < 1e-6
    return {"minimum_r_der_bytes": minimum_width,
            "assumed_point_sample_cost_in_digest_query_units": point_cost,
            "point_sample_bits": best, "expected_query_surrogate_bits": math.log2(q2),
            "optimistic_expected_input_cost_bits": math.log2(point_cost*2**best+q2),
            "quadrature_relative_difference": abs(q1/q2-1)}


def main():
    report = {"evidence": "locally-reproduced", "deployment_class": "unclassified",
              "scope": "Host cost models only; no native script or Core execution.",
              "exact_small_models": exhaustive(),
              "large_model": "Independent Poisson sparse width counts; common widths replaced by their mean; free classification; no memory, EC arithmetic, audit, or curve-independence claim.",
              "results": [optimize(c, a) for a in (24, 25) for c in (1, 2, 4, 16)],
              "all_expectations_met": True}
    output = HERE / "r8_portfolio_costs.json"
    output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report["results"], indent=2))


if __name__ == "__main__":
    main()
