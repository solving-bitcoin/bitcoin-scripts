# Exact equality of two opaque multisets

Can interleaving each untrusted deletion hint with its right-hand item
reduce Script cost for exact multiset equality of arbitrary raw byte
vectors? The hypothesis is that destructive routing buys linear script
growth at the cost of one hint for every match except the last. Compare
with an exhaustive greedy byte matcher on identical payload lists and
terminal predicates. All payload and hint items are hostile. Constraints
are 520-byte elements, at most 1,000 combined items, exact multiplicity,
canonical hints and the central compilation policy.

The entry suffix is
`left[0] ... left[n-1] right[0] right[1] hint[1] ... right[n-1] hint[n-1]`.
At a step with `p` left and `p` right items remaining, the top hint is
the depth `d` relative to the current left pool. Check `0 <= d < p` and
its exact ScriptNum encoding. Below that hint are `p` right items and
`p-2` future hints above the left pool. Therefore the roll argument is
`d + 2p - 2`. It addresses only the intended pool for a well-shaped
suffix. Move the selected raw value and verify it against the current
right value, consuming both. At one pair the last two items are already
adjacent. Each successful execution removes one left item for each right
item, with exact bytes preserved through each comparison. Duplicate values
can have multiple harmless deletion schedules.

The closest in-repo primitive is [destructive u4 sorting](u4-sort.md),
which verifies order over numeric nibbles. The interleaving here removes
the separate hint-routing step, and the checked relation is raw equality.
The source and PR search also found [PR #266](https://github.com/solving-bitcoin/bitcoin-scripts/pull/266),
which checks multiset equality for the 16-symbol u4 alphabet using packed
histograms. The opaque contract has no fixed numeric alphabet.
Routing follows the [pinned Bitcoin Core OP_ROLL semantics](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L759-L775)
and reuses the [four-byte canonicality helper](../../src/arithmetic/scriptint/README.md).

## Matched complete leaves

| Width | Schedule | Script bytes | Witness bytes | Ordinary items | Hint items | Serialized hint bytes | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Greedy | 74 | 25 | 8 | 0 | 0 | 10 | 38 |
| 4 | Hinted | 44 | 29 | 8 | 3 | 4 | 14 | 31 |
| 16 | Greedy | 1,477 | 97 | 32 | 0 | 0 | 34 | 599 |
| 16 | Hinted | 219 | 124 | 32 | 15 | 27 | 50 | 151 |
| Two of 16 | Greedy | 2,953 | 193 | 64 | 0 | 0 | 66 | 1,190 |
| Two of 16 | Hinted | 437 | 247 | 64 | 30 | 54 | 97 | 302 |

For invocation `b` at width `n`, left item `i` is the two bytes
`[0xc2+b, (7*i) mod (n-1)]`. Right item `i` is left item
`(5*i+2*b+1) mod n`. Generate each hint by finding the topmost match
and removing it from a host copy of the left list. Put all invocation
suffixes on the stack in increasing `b` order, with the last consumed
first. Both schedules include all matching, cleanup and a single terminal
true. Whole-script compilation uses optimizer `ALL`. Witness bytes include
all entry items and serialization overhead, excluding script, control
block, annex and transaction. Hint bytes include per-item length prefixes
and exclude the shared witness count prefix. The two width-16 hinted
invocations preload 94 total items. Neither schedule has caller data in
the measured leaf. Dynamic opcode counts include active non-push operations
and encountered branch delimiters. No signatures execute.

The evidence is `locally-reproduced` and execution is `unclassified`.
The local tapscript `Consensus` profile enables MINIMALIF, stack and element
limits, disables numeric minimality and experimental OP_CAT, and uses a
synthetic empty transaction. The compiler and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).

## Composition and hostile inputs

The public hinted generator supports `1..=332`. Its combined peak is
at most `3n+2` for `n>=2` and two for `n=1`, before any caller data or
future inputs. The first guard adds three temporary items to the
`3n-1` entry items. The width-332 test places 664 operand items, 331
hints and two caller sentinels at entry, reaches 1,000, and observes
both sentinels after execution. A third caller item rejects. In the
two-invocation fixture the first check sees all 64 ordinary items and
30 hints, so its peak is 97 rather than 50.

The fragment preserves both caller stacks given an exact suffix. It
consumes both lists and all hints and leaves no result items. The caller
must establish that boundary, bind application values and supply a
terminal predicate. Funded Core and relay checks are outside this
experiment. The tests compare both schedules with independently sorted
raw vectors, corrupt both hint positions in a duplicate fixture, try
all in-range reuse attempts on unequal multiplicities, cover 520- and
521-byte entries, and reject short and surplus standalone witnesses.

Greedy matching has higher script cost in the tested widths but keeps
the witness and stack smaller. Mere membership allows repeated use of
one left item. See the [negative result](../negative-results/opaque-multiset.md).

```sh
cargo test --locked --lib support::raw_multiset::tests
cargo test --locked --test primitive_metrics opaque_multiset_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation](../../src/support/raw_multiset/README.md) and
catalog `support/opaque-multiset`.
