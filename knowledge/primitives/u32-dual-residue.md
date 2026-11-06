# Joint u32 residues modulo 7 and 9

Can a common modulo-63 reduction recover both residues of a checked u32
more cheaply than two separate centered reductions? The hypothesis is
that a shared byte-weighted sum removes one copy of the word and shortens
the reduction ladders. Compare the same canonical byte guards, raw output
checks and terminal predicate. All witness items are hostile. The hard
constraints are four-byte ScriptNum operations, canonical byte limbs,
the combined 1,000-item limit, zero hints and the central compilation policy.
Evidence is `locally-reproduced`; execution is `unclassified`.

For four big-endian bytes `b0 b1 b2 b3`, the word is congruent to
`b0 + 16*b1 + 4*b2 + b3` modulo 63 because `256 ≡ 4` and `4³ ≡ 1`.
The weighted sum is at most 5,610. Subtract the descending powers-of-two
multiples of 63, once per power when the value is at least the multiple.
This is binary quotient subtraction and leaves a canonical value in
`0..=62`. Both 7 and 9 divide 63, so the same ladder can reduce that
small value for each output. The final stack order is `r7 r9`.

The separate baseline checks the same word once, then copies it. It
reduces `b0 + 2*b1 - 3*b2 + b3 + 770` modulo 7 and
`b0 - 2*b1 + 4*b2 + b3 + 513` modulo 9. Offsets are exact multiples
of their respective moduli and keep both intermediates nonnegative,
with upper bounds 1,790 and 2,043. The baseline uses the same
conditional-subtraction generator as the shared path. The closest recorded
single projection is [u32 modulo 65,537](u32-mod65537.md). Its folding
identity and output contract differ.
[Pinned source](https://github.com/solving-bitcoin/bitcoin-scripts/blob/87f324464d641e4263f696af3b0a4063c8c4ba94/src/arithmetic/u32/residue.rs).
The scoped search included the
catalog, source, comparisons, negative results and matching PRs.

## Matched complete leaves

| Word | Schedule | Script bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `01234567` | Shared mod 63 | 210 | 9 | 4 | 0 | 7 | 115 |
| `01234567` | Separate | 248 | 9 | 4 | 0 | 10 | 136 |
| `fedcba98` | Shared mod 63 | 210 | 13 | 4 | 0 | 7 | 113 |
| `fedcba98` | Separate | 248 | 13 | 4 | 0 | 10 | 136 |

Both scripts include all validation, computation, both byte-exact
output checks and terminal true. The entire checked leaf uses optimizer
`ALL`. Serialized witness sizes include all four entry items and their
prefixes, excluding script, control block, annex and transaction. Each
configuration has zero caller items and zero hints. The second word uses
four two-byte ScriptNums because each byte requires a sign pad. Dynamic
non-push counts include active operations and encountered branch delimiters.
No signatures execute.

The local tapscript `Consensus` profile enforces MINIMALIF and stack and
element limits, disables numeric minimality and experimental OP_CAT,
and uses a synthetic empty transaction. Canonical byte encoding is checked
in the script. The compiler and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
Funded Core and relay validation are outside this experiment.

## Composition and reproduction

The shared path consumes an exact four-item suffix and preserves both
caller stacks. It peaks at seven items plus all caller state, including
any preloaded future words. The test observes both caller stacks at
exactly 1,000 items and rejects one additional caller item. No hints are
required. To build a complete leaf, consume or verify both residues and
add a terminal predicate.

The test corpus varies all 256 values at every byte position, checks
both sides of the sign boundary and includes deterministic wider words.
Malformed values, noncanonical byte encodings, short or surplus witnesses
and oversized elements reject. The pair identifies a class modulo 63.
The two different words 42 and 105 pass the same output predicate, so
the original word needs independent binding where required. See the
[negative result](../negative-results/u32-dual-residue.md).

```sh
cargo test --locked --lib arithmetic::u32::dual_residue::tests
cargo test --locked --test primitive_metrics u32_dual_residue_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation README](../../src/arithmetic/u32/dual_residue/README.md)
and catalog record `arithmetic/u32-dual-residue`.
