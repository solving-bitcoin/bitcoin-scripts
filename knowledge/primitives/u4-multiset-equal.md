# Checked u4 multiset equality via packed histogram difference

## Research question and hypothesis

Can two equal-length hostile u4 vectors be tested for multiset equality with
no witness hints and far less script than building and comparing sixteen
per-symbol occurrence counts? The hypothesis is that one signed radix-`B`
lane per symbol, with `B = 2n + 1`, packs the whole histogram *difference*
into a few four-byte ScriptNum accumulators, so each nibble costs one
`OP_PICK` into a generation-time constant table per accumulator word. This is
a new local construction; no global novelty claim is made for packed
histograms or positional fingerprints.

## Contract and proof

`arithmetic::u4::multiset_equal::u4_nibbles_multiset_equal(n)`, `1 <= n <= 489`:

```text
preserved | a[0] ... a[n-1] | b[0] ... b[n-1]  ->  preserved | equal
```

`equal` is `1` iff the multisets of `a` and `b` agree, else `0`. A
nibble outside `0..=15` in either vector aborts the script.

Symbol `x` is assigned to word `x div L` and contributes the public constant
`B^(x mod L)`, added for `b` and subtracted for `a`. Each lane then holds
`count_b(x) - count_a(x)` in `-n..=n`; with `B = 2n + 1` that is a unique
balanced-radix digit, so a word is zero iff all its lanes are zero. `L` is the
largest integer with `B^L <= 2^32 - 1`, so every partial accumulator has
magnitude at most `(B^L - 1)/2 <= 2^31 - 1` and stays inside the four-byte
ScriptNum domain. The word count is `ceil(16/L)`. Because the checks, tables
and accumulators are generation-time constants, no witness data is trusted
except the nibbles themselves.

Each word pass pushes its 16-entry table, accumulates all `2n` inputs, tests
the accumulator for zero, `OP_BOOLAND`s the result into the running verdict on
the altstack and drops the table. The range check runs only in the first pass;
later passes reuse inputs already proved canonical. Surrounding main and alt
stack items are preserved.

## Threat model and evidence

All nibbles are hostile. The range check precedes the first use as a stack
index, which matters because `OP_PICK` of an unchecked value would silently
read a different slot instead of failing. Tests cover `-1`, `16`, and `255` at
several positions in both vectors, a `16` placed where it would alias an input
slot, adjacent-symbol and extreme-concentration lane aliasing attempts,
all 256 single-symbol pairs at length 8, deterministic shuffle/mutate vectors
at lengths 1/2/3/8/16 against a sorted-vector model, nonminimal numeric
encodings under a permissive profile, preserved main/alt state, generation
bounds, and the exact strict 1,000-item frontier at `n = 489` (accepted with
one preserved item, rejected with two).

Evidence is `locally-reproduced`; the model is ordinary Rust sorting, not an
independent Script interpreter. Execution is `unclassified`: the strict local
helper runs in a tapscript context with the stack limit enforced, and no
Bitcoin Core consensus or policy validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment, which is straight-line, so its 723 executed non-push opcodes equal the static count, with the 32-item canonical witness
(`a = 0..=15`, `b` reversed); input pushes, transaction framing and unrelated
state excluded; zero hint items, all 32 data items present at entry.

| Length | Words x lanes | Script bytes | Witness bytes | Combined peak |
| ---: | :---: | ---: | ---: | ---: |
| 4 | 2 x 10 | 275 | 16 | 29 |
| 8 | 3 x 7 | 637 | 32 | 37 |
| 16 | 3 x 6 | 1,158 | 63 | 53 |
| 64 | 4 x 4 | 5,523 | 249 | 149 |

(Length 16 is the README-tracked metric; all four sizes are pinned by
`multiset_equal::tests::recorded_sizes_are_current`.) The closest existing
route composes sixteen `u4_nibbles_count` calls per vector. Their bare
script sizes alone sum to 8,512 bytes at length 16 (`32 x 266`), before
copying each vector sixteen times and comparing the counts, so the packed
form is at least 7.3 times smaller there. That baseline is a lower-bound
estimate, not a built and measured comparator.

## Reproduction

```sh
cargo test --locked arithmetic::u4::multiset_equal::tests --lib
cargo test --locked --test primitive_metrics u4_multiset_equal_metrics_are_current -- --exact
python3 tools/kb.py validate
```
