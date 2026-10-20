# Checked u4 inversion count

## Research question and hypothesis

Can the exact number of inversions (pairs `i < j` with `a[i] > a[j]`) of a hostile
u4 vector be computed with no hints and no table, and when is that worth more
than the specialized nondecreasing check? The hypothesis is that one
`OP_PICK`/`OP_PICK`/`OP_GREATERTHAN`/`OP_ADD` quadruple per pair gives the
exact count after a single linear range check. This is a new local construction;
no global novelty claim is made for the elementary counting identity.

## Contract and proof

`arithmetic::u4::inversions::u4_nibbles_inversions(n)`, `1 <= n <= 128`:

```text
preserved | a[0] ... a[n-1]  ->  preserved | #{ i < j : a[i] > a[j] }
```

Each nibble is range-checked in `0..=15` once, then every unordered pair is
compared in place and the Boolean results are summed into one accumulator in
`0..=n(n-1)/2`. Equal nibbles are not inversions. The total is at most 8,128, far
inside the four-byte ScriptNum domain. The input is consumed and unrelated
stack state is preserved; the accumulator is parked on the altstack only during
cleanup. The length bound is script size (quadratic), not stack depth: the
peak is `n + 3 + preserved`.

## Threat model and evidence

All nibbles are hostile. Tests cover `-1`, `16` and `255` at every position of
a length-4 vector, exhaustive agreement with a Rust model for every vector of
length 1..=4, boundary vectors (fully descending 120, ascending 0, constant 0),
deterministic longer vectors up to 32, preserved main/alt state, generation
bounds, and a strict-stack-limit run at the length-128 maximum (peak 131).

For permutations of `0..=4`, the inversion count equals the digit sum of the
Lehmer code computed by `arithmetic::factoradic::lehmer_of_permutation`. This is a
cross-check against separately written Rust counting code, not an independent
Script implementation. Evidence is `locally-reproduced`; execution is
`unclassified` (strict local tapscript helper with the stack limit enforced); no
Bitcoin Core consensus or policy validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment, straight-line so executed non-push
opcodes equal the static count; input pushes, terminal predicate and transaction
framing excluded; zero hint items, all `n` data items present at entry. The
length-128 script exceeds the 32 KiB optimizer cutoff and is reported
unoptimized.

| Length | Pairs | Script bytes | Static non-push opcodes | Nondecreasing check |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 6 | 60 | 39 | 53 |
| 8 | 28 | 218 | 141 | 123 |
| 16 | 120 | 822 | 537 | 263 |
| 32 | 496 | 3,709 | 2,097 | 588 |
| 64 | 2,016 | 15,629 | 8,289 | 1,244 |
| 128 | 8,128 | 64,178 (unoptimized) | 32,962 | 2,556 |

Every size is pinned by `inversions::tests::recorded_sizes_are_current`; length
16 is also the README metric. Cost is quadratic: about 6.1 bytes per pair while
every `OP_PICK` depth is at most 16, rising toward 8 bytes per pair once
operand depths exceed 16 force three-byte pushes. The specialized
[nondecreasing predicate](u4-nondecreasing.md) answers "zero inversions" in
linear bytes and is 3.1 times smaller at 16 nibbles and 12.3 times smaller at 64,
so the count is only worth paying for when its magnitude (a disorder measure,
permutation parity, or a Kendall-tau distance to a known order) is consumed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::inversions::tests --lib
cargo test --locked --test primitive_metrics u4_inversions_metrics_are_current -- --exact
python3 tools/kb.py validate
```
