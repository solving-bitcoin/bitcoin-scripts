#!/usr/bin/env python3
"""Exact offchain extraction across a point-lock publication's ECDSA keys.

Inputs are public curve points and validated-context (key index, r, s, z)
rows. The caller authenticates the setup and derives the actual native z.
Only relations between reconstructed nonce points in a signed GLV orbit are
used. No private nonce input, scalar oracle, network or Bitcoin execution.
Unresolved means this linear system does not extract, not DLP impossibility.
"""
from collections import deque
import hashlib
import json
from pathlib import Path
import unittest

from nonce_relation_extraction import (
    G, N, P, SIGNED_ENDOMORPHISMS, add, mul, verify, extract_rows, scalar_fixture,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def checked_point(point):
    if (not isinstance(point, tuple) or len(point) != 2
            or any(type(v) is not int or not 0 <= v < P for v in point)
            or (point[1] * point[1] - point[0] ** 3 - 7) % P):
        raise ValueError('invalid secp256k1 point')
    return point


def nonce_orbit(point):
    """Return canonical U and known m with actual R=m*U, including its sign."""
    orbit = [((beta * point[0] % P, sign * point[1] % P), a)
             for a, (beta, sign) in SIGNED_ENDOMORPHISMS.items()]
    canonical, inverse_multiplier = min(orbit)
    return canonical, pow(inverse_multiplier, -1, N)


def analyze_publication(keys, rows):
    """Solve the validated bipartite key/nonce linear system componentwise.

    Each edge is u=A*d+B, where R=m*U and A=r/(s*m), B=z/(s*m).
    All edge multipliers are nonzero. A connected component has linear
    nullity one unless a nondegenerate cycle fixes its root. Duplicate key
    points merge. Known affine relations between different key points, and
    nonce translations outside signed GLV orbits, are not searched here.
    """
    keys = [checked_point(key) for key in keys]
    rows = list(rows)
    key_nodes = [('key', key) for key in keys]
    adjacency = {node: [] for node in key_nodes}
    edges = []
    for row_index, row in enumerate(rows):
        if (not isinstance(row, (tuple, list)) or len(row) != 4
                or any(type(v) is not int for v in row)):
            raise ValueError('row must contain four integers')
        index, r, s, z = row
        if not (0 <= index < len(keys) and 0 < r < N and 0 < s < N and 0 <= z < N):
            raise ValueError('noncanonical ECDSA row')
        valid, nonce = verify(z, r, s, keys[index])
        if not valid:
            raise ValueError('invalid ECDSA equation')
        canonical, multiplier = nonce_orbit(nonce)
        left, right = key_nodes[index], ('nonce', canonical)
        inverse = pow(s * multiplier % N, -1, N)
        a, b = r * inverse % N, z * inverse % N
        edges.append((left, right, a, b))
        adjacency[left].append((right, a, b, row_index))
        inverse_a = pow(a, -1, N)
        adjacency.setdefault(right, []).append((left, inverse_a, -b * inverse_a % N, row_index))

    # All public inputs and ECDSA rows have been validated before extraction.
    remaining = set(adjacency)
    recovered = {}
    components = []
    while remaining:
        root = min(remaining)
        expressions = {root: (1, 0)}
        queue = deque([root])
        tree_edges, edge_ids = set(), set()
        while queue:
            node = queue.popleft()
            aa, bb = expressions[node]
            for other, a, b, edge_index in adjacency[node]:
                edge_ids.add(edge_index)
                if other not in expressions:
                    expressions[other] = (a * aa % N, (a * bb + b) % N)
                    tree_edges.add(edge_index)
                    queue.append(other)
        remaining.difference_update(expressions)
        root_scalar = None
        fixing_rows, degenerate_rows = [], []
        for edge_index in sorted(edge_ids - tree_edges):
            left, right, a, b = edges[edge_index]
            al, bl = expressions[left]
            ar, br = expressions[right]
            denominator = (ar - a * al) % N
            numerator = (a * bl + b - br) % N
            if denominator == 0:
                if numerator != 0:
                    raise AssertionError('inconsistent verified cycle')
                degenerate_rows.append(edge_index)
                continue
            candidate = numerator * pow(denominator, -1, N) % N
            if root_scalar is not None and candidate != root_scalar:
                raise AssertionError('inconsistent independently fixing cycles')
            root_scalar = candidate
            fixing_rows.append(edge_index)
        if root_scalar is not None:
            for node, (a, b) in expressions.items():
                scalar = (a * root_scalar + b) % N
                if mul(scalar) != node[1]:
                    raise AssertionError('extracted scalar does not match public point')
                recovered[node] = scalar
        components.append(dict(
            key_indices=[i for i, node in enumerate(key_nodes) if node in expressions],
            nodes=len(expressions), edges=len(edge_ids),
            nonce_orbits=sum(node[0] == 'nonce' for node in expressions),
            linear_rank=len(expressions) - (root_scalar is None),
            linear_nullity=int(root_scalar is None),
            fixing_cycle_rows=fixing_rows, degenerate_cycle_rows=degenerate_rows,
        ))
    return dict(key_scalars=[recovered.get(node) for node in key_nodes],
                signature_rows=len(rows), components=components,
                nonce_orbits=sum(node[0] == 'nonce' for node in adjacency),
                method='validated-cross-key-nonce-graph')


def signed_row(key_index, secret, nonce, digest, *, negate_s=False):
    """Deterministic synthetic research row; secrets never reach the extractor."""
    r = mul(nonce)[0] % N
    s = (digest + r * secret) * pow(nonce, -1, N) % N
    if negate_s:
        s = N - s
    return key_index, r, s, digest


def lifted_unknown_log(tag):
    x = scalar_fixture(tag) % P
    while True:
        y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
        if y * y % P == (x ** 3 + 7) % P:
            return x, y
        x = (x + 1) % P


def degenerate_fixture():
    """Three public unknown-log keys, six shared nonces, equal z per round.

    No scalar of X is computed: P_i=u_i*X+11G, R_j=a_j*X,
    s_ij=r_j*u_i/a_j, z_j=-11*r_j. This is deliberately synthetic ECDSA,
    not cap60 or a Bitcoin hash-preimage construction.
    """
    base = lifted_unknown_log('cross-key/unknown-log-base')
    coefficients = (7, 13, 17)
    keys = [add(mul(u, base), mul(11)) for u in coefficients]
    rows = []
    for a in (1, 19, 23, 29, 31, 37):
        r = mul(a, base)[0] % N
        rows += [(i, r, r * u * pow(a, -1, N) % N, -11 * r % N)
                 for i, u in enumerate(coefficients)]
    return keys, rows


def dense_rank(keys, rows):
    """Independent small-test Gaussian elimination, not the extraction path."""
    nonce_ids = {}
    reduced = []
    for key_index, r, s, z in rows:
        valid, nonce = verify(z, r, s, keys[key_index])
        if not valid:
            raise ValueError('invalid test row')
        canonical, multiplier = nonce_orbit(nonce)
        column = nonce_ids.setdefault(canonical, len(nonce_ids))
        reduced.append((key_index, column, r, s * multiplier % N))
    matrix = []
    for key_index, nonce_index, r, s in reduced:
        row = [0] * (len(keys) + len(nonce_ids))
        row[key_index], row[len(keys) + nonce_index] = -r % N, s
        matrix.append(row)
    pivot = 0
    for col in range(len(keys) + len(nonce_ids)):
        selected = next((i for i in range(pivot, len(matrix)) if matrix[i][col]), None)
        if selected is None:
            continue
        matrix[pivot], matrix[selected] = matrix[selected], matrix[pivot]
        inverse = pow(matrix[pivot][col], -1, N)
        matrix[pivot] = [v * inverse % N for v in matrix[pivot]]
        for i in range(pivot + 1, len(matrix)):
            multiplier = matrix[i][col]
            matrix[i] = [(v - multiplier * w) % N for v, w in zip(matrix[i], matrix[pivot])]
        pivot += 1
    return pivot


class CrossKeyTests(unittest.TestCase):
    def fixture(self):
        secrets = [scalar_fixture(f'cross-key/key/{i}') for i in range(2)]
        nonces = [scalar_fixture(f'cross-key/nonce/{j}') for j in range(2)]
        digests = [scalar_fixture(f'cross-key/digest/{j}') for j in range(2)]
        rows = [signed_row(i, secret, nonce, z) for i, secret in enumerate(secrets)
                for nonce, z in zip(nonces, digests)]
        return secrets, [mul(d) for d in secrets], nonces, digests, rows

    def test_common_contexts_cross_key_only_extraction(self):
        secrets, keys, _, _, rows = self.fixture()
        for i, key in enumerate(keys):
            self.assertIsNone(extract_rows(key, [row[1:] for row in rows if row[0] == i]))
        result = analyze_publication(keys, rows)
        self.assertEqual(result['key_scalars'], secrets)
        self.assertEqual(result['components'][0]['linear_rank'], 4)
        self.assertEqual(dense_rank(keys, rows), 4)
        # Input order does not affect the recovered result.
        self.assertEqual(analyze_publication(keys, list(reversed(rows)))['key_scalars'], secrets)

    def test_all_signed_glv_relations_and_high_s(self):
        secrets, keys, nonces, digests, _ = self.fixture()
        for multiplier in SIGNED_ENDOMORPHISMS:
            for flip in (False, True):
                with self.subTest(multiplier=multiplier, negate_s=flip):
                    rows = [signed_row(0, secrets[0], k, z) for k, z in zip(nonces, digests)]
                    rows += [signed_row(1, secrets[1], multiplier * k % N, z, negate_s=flip)
                             for k, z in zip(nonces, digests)]
                    result = analyze_publication(keys, rows)
                    self.assertEqual(result['key_scalars'], secrets)
                    self.assertEqual(result['nonce_orbits'], 2)
                    self.assertEqual(dense_rank(keys, rows), 4)

    def test_three_key_cycle_without_any_double_pair_collision(self):
        secrets = [scalar_fixture(f'cross-key/triangle/key/{i}') for i in range(3)]
        keys = [mul(d) for d in secrets]
        rows = []
        for j, pair in enumerate(((0, 1), (1, 2), (2, 0))):
            nonce = scalar_fixture(f'cross-key/triangle/nonce/{j}')
            z = scalar_fixture(f'cross-key/triangle/digest/{j}')
            rows += [signed_row(i, secrets[i], nonce, z) for i in pair]
        for i, key in enumerate(keys):
            self.assertIsNone(extract_rows(key, [row[1:] for row in rows if row[0] == i]))
        result = analyze_publication(keys, rows)
        self.assertEqual(result['key_scalars'], secrets)
        self.assertEqual(result['components'][0]['linear_rank'], 6)
        self.assertEqual(dense_rank(keys, rows), 6)

    def test_exact60_cross_key_and_anchor_targets(self):
        from anchored_extraction import small_s_check, der
        from core_check import unpack_signature
        from publication_core_check import encode_key
        secrets, keys, nonces, _, _ = self.fixture()
        target_scalars = []
        targets, anchor_rows, rows = [], [], []
        for i, secret in enumerate(secrets):
            target_scalar = scalar_fixture(f'cross-key/target/{i}')
            while not 0 < encode_key(mul(target_scalar))[1] < 128:
                target_scalar = (target_scalar + 1) % N
            target = mul(target_scalar)
            rt = target[0]
            self.assertEqual(len(der(rt, 1)), 40)
            target_scalars.append(target_scalar)
            targets.append(target)
            anchor_rows.append((i, rt, 1, (target_scalar - rt * secret) % N))
            for j, nonce in enumerate(nonces):
                sigma, digest = small_s_check(secret, nonce, 3 + 5 * i + j)
                self.assertEqual(len(sigma), 60)
                r, s, _ = unpack_signature(sigma)
                rows.append((i, r, s, int.from_bytes(digest, 'big')))
        for i, key in enumerate(keys):
            self.assertIsNone(extract_rows(key, [row[1:] for row in anchor_rows + rows if row[0] == i]))
        result = analyze_publication(keys, anchor_rows + rows)
        self.assertEqual(result['key_scalars'], secrets)
        for i, rt, _, z0 in anchor_rows:
            t = (rt * result['key_scalars'][i] + z0) % N
            self.assertEqual((t, mul(t)), (target_scalars[i], targets[i]))

    def test_six_shared_contexts_can_have_only_degenerate_cycles(self):
        keys, rows = degenerate_fixture()
        result = analyze_publication(keys, rows)
        self.assertEqual(result['key_scalars'], [None] * 3)
        component, = result['components']
        self.assertEqual((component['nodes'], component['edges'], component['linear_rank']), (9, 18, 8))
        self.assertEqual(len(component['degenerate_cycle_rows']), 10)
        self.assertEqual(component['fixing_cycle_rows'], [])
        self.assertEqual(dense_rank(keys, rows), 8)
        for start in range(0, 18, 3):
            self.assertEqual(len({row[3] for row in rows[start:start+3]}), 1)

    def test_one_shared_nonce_and_disconnected_keys_do_not_overextract(self):
        secrets, keys, nonces, digests, rows = self.fixture()
        one_round = [signed_row(i, d, nonces[0], digests[0]) for i, d in enumerate(secrets)]
        result = analyze_publication(keys, one_round)
        self.assertEqual(result['key_scalars'], [None, None])
        self.assertEqual(result['components'][0]['linear_nullity'], 1)
        other_secret = scalar_fixture('cross-key/independent/key')
        all_keys = keys + [mul(other_secret)]
        more = [signed_row(2, other_secret, scalar_fixture(f'cross-key/unrelated/{j}'), digests[j])
                for j in range(2)]
        result = analyze_publication(all_keys, rows + more)
        self.assertEqual(result['key_scalars'], secrets + [None])
        self.assertEqual(sum(c['linear_rank'] for c in result['components']), dense_rank(all_keys, rows + more))

    def test_duplicate_keys_zero_rows_and_digest_boundaries(self):
        secrets, keys, nonces, _, _ = self.fixture()
        rows = [signed_row(0, secrets[0], nonces[0], 0),
                signed_row(1, secrets[0], nonces[0], N - 1)]
        self.assertEqual(analyze_publication([keys[0], keys[0]], rows)['key_scalars'], [secrets[0]] * 2)
        result = analyze_publication(keys, [])
        self.assertEqual(result['key_scalars'], [None, None])
        self.assertEqual([c['linear_rank'] for c in result['components']], [0, 0])
        self.assertEqual(analyze_publication([], [])['components'], [])

    def test_invalid_public_inputs_rejected_even_after_extractable_rows(self):
        _, keys, _, _, rows = self.fixture()
        i, r, s, z = rows[0]
        invalid = [(-1,r,s,z), (2,r,s,z), (i,0,s,z), (i,N,s,z), (i,r,0,z),
                   (i,r,N,z), (i,r,s,N), (i,r,s,-1), (i,r,s,(z+1)%N),
                   (i,r,s), (i,r,s,True)]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(ValueError):
                analyze_publication(keys, rows + [row])
        for key in (None, (1,1), (P,G[1]), (True,G[1])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                analyze_publication([key], [])


if __name__ == '__main__':
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'nonce_relation_extraction.py', HERE/'anchored_extraction.py',
             HERE/'core_check.py', HERE/'publication_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        tests_run=program.result.testsRun, failures=0, errors=0,
        scope='Synthetic ECDSA algebra; no Bitcoin execution or native hash preimages.',
        signed_glv_and_sign_cases=12, exact60_cross_key_target_extractions=2,
        degenerate_six_round_graph=dict(keys=3, nonces=6, rows=18, rank=8, nullity=1),
        incremental_onchain_bytes=0, incremental_onchain_hint_items=0,
        general_extraction_proved=False,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'cross-key-nonce-extraction.json').write_text(json.dumps(report, indent=2)+'\n')
