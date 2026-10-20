# Nibble-packed bracket-balance check

## Research question and hypothesis

Can a hostile bracket string packed four brackets per nibble be tested for
balance with no hints, and how much smaller is that than scanning one item per
bracket? The hypothesis is that each nibble is an element of the
(net change, prefix deficit) monoid, so two 16-entry tables replace four
bracket steps by one lookup pair. This is a new local construction; no global
novelty claim is made for the monoid summary of a Dyck-word check.

## Contract and proof

`arithmetic::u4::balanced::u4_nibbles_balanced(n)`, `1 <= n <= 963`:

```text
preserved | v[0] ... v[n-1]  ->  preserved | balanced
```

Nibble `b3 b2 b1 b0` encodes four brackets, most significant bit first, `1` =
open and `0` = close, and `v[0]` holds the first four brackets. A nibble has net
change `D` and prefix deficit `R = -min(0, min prefix)`. With height `h` before
it, the nibble keeps every prefix nonnegative iff `h >= R` and leaves
`h + D`. The fragment tracks `h` and the minimum of `h - R` over all nibbles;
the string is balanced iff that minimum is nonnegative and the final height is
zero. Output is `1` or `0`. A nibble outside `0..=15` aborts before it indexes
a table. Tables (32 resident items) are generation-time constants; unrelated
stack state is preserved.

## Threat model and evidence

Every nibble is hostile. Tests cover `-1`, `16` and `255` at every position of a
length-4 batch, exhaustive agreement with a bracket-by-bracket Rust model for
every one to three nibbles (4,368 vectors), 200 random Dyck words and 200 random
strings at each of 4, 8 and 16 nibbles (at least 20 accepted and 20 rejected
each), first-nibble-first ordering, preserved main/alt state, generation bounds,
and an exact stack frontier (accepted at 963 nibbles with a 1,000-item peak, and
rejected with `StackSize` when more live items are added). A first draft rolled the
top input instead of the deepest and was rejected by the exhaustive test; the
checked version rolls the deepest.

The comparator `bracket_items_balanced` scans one item per bracket from the top
with open and close exchanged (a reversed, complemented balanced string is
balanced) and is checked against the same model. Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hint items; all data items present at entry. Fixture: `(())`
repeated 32 times (128 brackets).

| Form | Script bytes | Witness bytes | Witness items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Nibble-packed | 895 | 65 | 32 | 69 | 598 |
| One item per bracket | 2,059 | 193 | 128 | 133 | 1,669 |

Script bytes by length (all pinned by `balanced::tests::recorded_sizes_are_current`):

| Brackets | 4 | 8 | 16 | 32 | 64 | 128 | 256 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Packed | 89 | 115 | 167 | 271 | 479 | 895 | 1,727 |
| One item each | 75 | 139 | 267 | 523 | 1,035 | 2,059 | 4,107 |

The packed form costs about 26 bytes per nibble plus a fixed 63-byte table cost,
against about 16 bytes per bracket, so it is 2.3 times smaller at 128 brackets and
2.4 times at 256, and loses only at four brackets (89 versus 75). Both forms
fit the 1,000-item stack limit with room to spare at these sizes, but the
packed form needs a 38-item minimum peak for its tables.

## Reproduction

```sh
cargo test --locked arithmetic::u4::balanced::tests --lib
cargo test --locked --test primitive_metrics u4_balanced_metrics_are_current -- --exact
python3 tools/kb.py validate
```
