# Longest common prefix of opaque item vectors

Can scanning a fixed-width pair of raw vectors backward remove the
forward scan's active-state register? The hypothesis is that replacing
the candidate on each mismatch gives a smaller leaf and peak while
preserving the same prefix length. Compare the same split witness
layout, raw-byte comparisons and terminal output check. Every payload
is hostile. The hard constraints are 520-byte elements, at most 1,000
combined items, zero hints and the central compilation policy. Evidence
is `locally-reproduced`; execution is `unclassified`.

The entry suffix is `left[0] ... left[n-1] right[0] ... right[n-1]`.
Initialize the candidate to `n` and compare indices `n-1` down to zero.
For position `i`, swapping the candidate with the top right item places
`i` remaining right items, the candidate and the selected right item
above the matching left item. A fixed roll of depth `i+2` aligns the
pair. Exact byte equality consumes both values. On a mismatch replace
the candidate with `i`; an equal pair leaves it alone. The final
candidate is the smallest mismatch position or `n` for full equality.
The forward comparator tracks an active bit and a running count,
incrementing only while every pair so far matches.

The semantic reference is
[C++ working draft N4950, §[alg.mismatch]](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/n4950.pdf).
The depth convention follows [pinned Bitcoin Core OP_ROLL](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L759-L775).
The scoped catalog, comparisons, source, negative-result and PR search
found the [u4 lexicographic comparator](u4-lexicographic.md) as the closest
prior interface. It returns an ordering predicate over checked numeric
digits. This construction returns the whole-item prefix length over
uninterpreted raw bytes.

## Cost boundary

| Pairs | Schedule | Script bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | Reverse mismatch | 292 | 193 | 64 | 0 | 66 | 165 |
| 32 | Forward state | 334 | 193 | 64 | 0 | 67 | 225 |
| 128 | Reverse mismatch | 1,256 | 771 | 256 | 0 | 258 | 657 |
| 128 | Forward state | 1,458 | 771 | 256 | 0 | 259 | 897 |

For width 32, the first mismatch is at index 5. For width 128, it is at
index 17. Left item `i` is `[0xab, i]`, and right item `i` matches except
at the first mismatch and every seventh position after it, where the
first byte becomes `0xcd`. Each complete leaf checks the exact canonical
length and leaves true. Whole-leaf optimizer `ALL` applies to every cost
fixture. Witness bytes include all ordinary entry items and count/length
prefixes, excluding script, control block, annex and transaction.
All `2n` items coexist at entry, and both schedules use zero hints and
zero caller items. Executed counts include active non-push opcodes and
encountered branch delimiters. No signatures execute.

The local tapscript `Consensus` profile uses synthetic transaction context,
with stack and element limits and MINIMALIF enabled and numeric minimality
and experimental OP_CAT disabled. The compiler and interpreter are pinned to
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).

## Caller boundary and reproduction

The public generator accepts `0..=499`. The reverse scan peaks at most
`2n+2` plus caller state for nonzero `n), or one plus caller state for
empty input. It reaches 1,000 for 499 pairs alone and for 498 pairs with
one preserved main and one alt item. An extra caller item rejects. The
forward comparator peaks at 999 for 498 pairs alone and rejects 499.
With an exact input suffix, both consume the two vectors and preserve
caller state.
Neither certifies the meaning or authenticity of the payloads.

Tests enumerate binary raw vectors through width five and compare the
result with a host forward prefix count. They exercise byte-exact distinctions
between empty and negative zero, a valid 520-byte payload, a 521-byte
item after the first mismatch, short and surplus entry items, wrong
terminal lengths, and observable preservation of both caller stacks.
A total equality count can include matches after a mismatch and differs
from this result. See the [negative result](../negative-results/opaque-common-prefix.md).

```sh
cargo test --locked --lib support::common_prefix::tests
cargo test --locked --test primitive_metrics opaque_common_prefix_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation README](../../src/support/common_prefix/README.md)
and catalog `support/opaque-common-prefix`.
