# Canonical small-permutation rank decoder

The bounded quotient arithmetic is shared with
[`scriptint::bounded`](../scriptint/README.md#bounded-division-without-quotient-hints).
This decoder calls the crate-private arithmetic core with its already-proven
canonical residual bound. The public arithmetic API adds hostile-input checks;
the existing permutation metric snapshots remain unchanged.

Decode one hostile canonical ScriptNum into the lexicographic permutation of
`0..width-1`. This is a representation adapter; it supplies neither authentication
nor a spending authorization. A separate Lehmer-digit decoder is the measured
baseline. Both consume a shrinking trusted symbol pool, so no symbol can repeat.

## Parameters

`width` is public and must be in `1..=12`, with no default. `permutation_count`
returns `width!`. The packed rank must be in `0..width!` and minimally encoded;
12! is 479,001,600, while 13! exceeds the four-byte positive ScriptNum domain.
Separate digits have bounds `d[i] < width-i`; the last digit is implicitly zero.
For a permutation `p`, `d[i]` counts later symbols smaller than `p[i]`, and
`rank = sum(d[i] * (width-1-i)!)`. For example, width 4 and rank 13 decode
to `[2, 0, 3, 1]`, with `2` on top of the output stack.

## Script metrics

`complete-leaf:` canonical/range checks, pool setup, decoding, pool cleanup,
all output comparisons against the descending permutation, and clean `OP_TRUE`
are included. Input pushes and transaction framing are excluded. Witness bytes
serialize the complete data vector, including its count and item-length prefixes;
leaf and control block are excluded. These descending-permutation witnesses attain
maximum canonical data-witness sizes for each width. All sizes use the policy's
optimized serialization (below 32 KiB).

| Encoding | Locking bytes | Data witness bytes | Data items | Combined peak | Executed non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| rank, width 4 | <!-- metric:permutation_rank_4_script -->102<!-- /metric:permutation_rank_4_script --> | <!-- metric:permutation_rank_4_witness -->3<!-- /metric:permutation_rank_4_witness --> | <!-- metric:permutation_rank_4_items -->1<!-- /metric:permutation_rank_4_items --> | <!-- metric:permutation_rank_4_stack -->8<!-- /metric:permutation_rank_4_stack --> | <!-- metric:permutation_rank_4_executed -->70<!-- /metric:permutation_rank_4_executed --> |
| digits, width 4 | <!-- metric:permutation_digits_4_script -->57<!-- /metric:permutation_digits_4_script --> | <!-- metric:permutation_digits_4_witness -->7<!-- /metric:permutation_digits_4_witness --> | <!-- metric:permutation_digits_4_items -->3<!-- /metric:permutation_digits_4_items --> | <!-- metric:permutation_digits_4_stack -->10<!-- /metric:permutation_digits_4_stack --> | <!-- metric:permutation_digits_4_executed -->37<!-- /metric:permutation_digits_4_executed --> |
| rank, width 8 | <!-- metric:permutation_rank_8_script -->312<!-- /metric:permutation_rank_8_script --> | <!-- metric:permutation_rank_8_witness -->5<!-- /metric:permutation_rank_8_witness --> | <!-- metric:permutation_rank_8_items -->1<!-- /metric:permutation_rank_8_items --> | <!-- metric:permutation_rank_8_stack -->12<!-- /metric:permutation_rank_8_stack --> | <!-- metric:permutation_rank_8_executed -->178<!-- /metric:permutation_rank_8_executed --> |
| digits, width 8 | <!-- metric:permutation_digits_8_script -->129<!-- /metric:permutation_digits_8_script --> | <!-- metric:permutation_digits_8_witness -->15<!-- /metric:permutation_digits_8_witness --> | <!-- metric:permutation_digits_8_items -->7<!-- /metric:permutation_digits_8_items --> | <!-- metric:permutation_digits_8_stack -->18<!-- /metric:permutation_digits_8_stack --> | <!-- metric:permutation_digits_8_executed -->85<!-- /metric:permutation_digits_8_executed --> |
| rank, width 12 | <!-- metric:permutation_rank_12_script -->633<!-- /metric:permutation_rank_12_script --> | <!-- metric:permutation_rank_12_witness -->6<!-- /metric:permutation_rank_12_witness --> | <!-- metric:permutation_rank_12_items -->1<!-- /metric:permutation_rank_12_items --> | <!-- metric:permutation_rank_12_stack -->16<!-- /metric:permutation_rank_12_stack --> | <!-- metric:permutation_rank_12_executed -->302<!-- /metric:permutation_rank_12_executed --> |
| digits, width 12 | <!-- metric:permutation_digits_12_script -->201<!-- /metric:permutation_digits_12_script --> | <!-- metric:permutation_digits_12_witness -->23<!-- /metric:permutation_digits_12_witness --> | <!-- metric:permutation_digits_12_items -->11<!-- /metric:permutation_digits_12_items --> | <!-- metric:permutation_digits_12_stack -->26<!-- /metric:permutation_digits_12_stack --> | <!-- metric:permutation_digits_12_executed -->133<!-- /metric:permutation_digits_12_executed --> |

Each row uses **0 hint items (0 hint bytes)**. Dynamic opcode counts come from
stepping the final compiled leaf with the interpreter's condition-stack state;
non-push conditional handlers count even when their enclosed branch is skipped.
Skipped arithmetic and all pushes are excluded. The interpreter's own tapscript
`opcode_count` counts parsed pushes and skipped instructions, so it is not used
as this dynamic metric. No signature budget is consumed; data-only execution
does not establish a complete-witness validation budget.

Provenance is printed from the binary's embedded lockfile: compiler
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, interpreter
`a09e87af444034698697f0a2267e755cf72f9aed`. Context is local tapscript,
`enforce_stack_limit=true`, `require_minimal=false`; raw canonicality is enforced
by the fragments themselves. Evidence: `locally-reproduced`; deployment:
`unclassified`. These are local complete leaves, without a transaction or Core.

## Security

There is no cryptographic security claim. The canonicality helper rejects
negative zero, padded ScriptNums, and operands longer than four bytes. A rank
range check runs before pool setup. Each bounded quotient is derived internally;
no quotient hints can redirect selection into preserved caller state. At a stage
with `m` symbols, `r < m!` implies `q=floor(r/(m-1)!) < m`; subtraction yields
a new residual below `(m-1)!`. `OP_ROLL` destructively selects one symbol and
preserves the relative order of the others. Final residual zero is checked.
This establishes the ordinary factoradic bijection, not message authentication.

## Script compatibility and standardness

Bare script: opcode-compatible, but custom output relay policy is untested.
P2SH: widths 4/8 measured leaves fit the 520-byte redeemScript element bound;
the 633-byte width-12 rank leaf exceeds it. P2WSH: measured leaves fit the
10,000-byte size bound, but the width-12 rank leaf has 354 static non-push
opcodes and violates the 201-opcode limit. Widths 4/8 rank leaves have 74/198;
digit leaves have 37/85/133. Tapscript: those legacy size/opcode limits are
absent; stack and element bounds still apply. No complete transaction or relay
policy acceptance is established. See [script types](../../../docs/script-types.md)
and [standardness](../../../docs/standardness.md).

## Witness and hints

Rank encoding: **one data item**, minimally encoded ScriptNum, present at entry.
Digit encoding: **width-1 data items**, reverse stage order in the witness vector,
so `d[0]` is on top. Each digit is a canonical ScriptNum. Neither encoding has
mandatory or optional auxiliary hints: **0 per invocation**, and **0 for k
invocations**. All k rank items or `k*(width-1)` digit items coexist at entry
when preloaded. A rank is public on opening; it carries no hiding guarantee.

For widths 4/8/12, standalone combined peaks are `width+4` for rank decoding and
`2*width+2` for separate digits. Main and altstack caller state add one item each
to these peaks. Exact 1,000-item tests preserve both kinds of caller state and
reject one additional item. The formulas are documented for those tested widths,
not an untested general composition claim. For k preloaded invocations, count
unconsumed payloads, retained outputs, and consumer state at every boundary;
output expansion still needs width items even though the rank enters as one.

## Stack contract

Rank: `preserved | rank -> preserved | p[width-1] ... p[0]`.
Digits: `preserved | d[width-2] ... d[0] -> preserved | p[width-1] ... p[0]`.
The first permutation symbol is **on top**. Existing altstack items are preserved;
selected symbols are staged above them and all temporary altstack items are
removed. Callers must consume every output and provide a terminal predicate.

## Operational notes

The rank encoding saves witness bytes and peak items, but loses combined script
plus data-witness bytes to separate digits at widths 4/8/12: 105/317/639 versus
64/144/224. It is useful as a measured low-entry-item representation point,
not a byte-efficiency improvement. The binary threshold decoder avoids disabled
division; the existing hinted division instead adds a witness obligation per
quotient. It is unnecessary for this small bounded alphabet.

Tests exhaust all 873 permutations across widths 1..6 using independent
lexicographic successor enumeration, cover boundary ranks through width 12,
reject missing/extra data, aliases, over-range ranks/digits and overlong items,
and verify preserved state and the exact stack frontier. Broader signature
multiset unranking remains outside this API.

## Knowledge-base integration

See [the knowledge page](../../../knowledge/primitives/factoradic-permutation.md),
[arithmetic comparison](../../../knowledge/comparisons/arithmetic.md),
[negative result](../../../knowledge/negative-results/factoradic-permutation.md),
and catalog record `arithmetic/factoradic-permutation`. Mathematical provenance:
Paul Tarau, [arXiv:0808.0554v1, §§7.1–7.2](https://arxiv.org/html/0808.0554v1).
The bounded Script threshold circuit and measured tradeoffs are local results.

Reproduce with:

```sh
cargo test --locked arithmetic::permutation --lib
cargo test --locked --test primitive_metrics permutation_rank_metrics_are_current -- --exact --nocapture
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```
