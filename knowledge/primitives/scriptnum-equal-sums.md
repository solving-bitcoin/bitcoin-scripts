# Exact equality of two signed ScriptNum sums

Can Script verify `a + b = c + d` across its full four-byte signed operand
domain without widening each operand into limbs? The hypothesis is that
`OP_ADD` produces a unique byte encoding even when a sum needs five bytes.
Comparing those encodings should remove carry work while preserving exact
integer equality. Compare with a radix-2³⁰ carry schedule over the same
hostile four-item witness and terminal predicate. The hard constraints are
the four-byte arithmetic input limit, the 1,000-item combined stack limit,
the central compilation policy and zero witness hints.

The fragment consumes `a b c d` and leaves both caller stacks as they were
below that exact suffix. It adds the right pair, stages the result on altstack,
adds the left pair, restores the right sum and applies `OP_EQUALVERIFY`.
The range of each sum is `−4,294,967,294..=4,294,967,294`. Canonical
sign-magnitude encoding is injective on this range, so comparing the two
encodings checks the integer relation without another numeric parse. Core's
operand/result distinction is specified in the pinned
[CScriptNum implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211-L250).
The two-limb reference splits each operand as `q * 2³⁰ + r` with
`0 <= r < 2³⁰`. It normalizes one remainder carry per pair and compares both
components. Each temporary numeric value fits in four bytes.

The scoped search covered the catalog, arithmetic comparisons, negative
results, source and matching PRs. The closest repository approaches are
bounded-limb arithmetic and centered residues. Their representations allow
further arithmetic, whereas this fragment only verifies equality. Open
[PR #277](https://github.com/solving-bitcoin/bitcoin-scripts/pull/277)
counts occurrences of u4 symbols using packed lanes. It checks a separate
relation.

## Measured complete leaves

Each fixture uses four copies of `2³¹−1` or four copies of `−(2³¹−1)`.
Each script checks the relation, then leaves true. Policy `ALL` compiles
the whole leaf. Witness bytes include the count and length prefixes of all
four ordinary data items, excluding script, control block, annex and
transaction. There are zero hints and no caller state. The local tapscript
`Consensus` profile enforces stack limits and MINIMALIF and disables
global numeric minimality and experimental OP_CAT. Dynamic non-push counts
include active operations and encountered branch delimiters. No signatures
execute. Local metrics are `locally-reproduced` and `unclassified`.

| Comparator | Leaf bytes | Data witness bytes | Data / hint items | Max combined peak | Executed non-push ops, positive / negative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Byte equality | 6 | 21 | 4 / 0 | 4 | 5 / 5 |
| Two carry limbs | 240 | 21 | 4 / 0 | 7 | 95 / 91 |

The raw schedule peaks at entry, so with `p` live caller items the combined
peak is `p + 4`. A witness supplies all four ordinary operands per call.
Preloading independent invocations also preloads all their operands.
There are still zero hints. Caller-owned data must establish the suffix
boundary and bind any input values the application relies on. An arbitrary
witness can choose a valid relation freely. Numeric aliases follow the
execution profile. When a consumer needs exact bytes, check operands
separately with [ScriptNum canonicality](../../src/arithmetic/scriptint/README.md).
The result is a predicate. Wider encodings cannot feed later numeric
operations or serve as a full-width amount representation.

## Funded Core comparison

The runner funds and verifies eight exact Taproot script-path spends against
the hash-pinned Bitcoin Core v30.3 binary, source revision
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. It checks block acceptance with
`generateblock` and relay policy separately with `testmempoolaccept` under
`-acceptnonstdtxn=0`. The manifest SHA-256 was
`917b479869a5bf29cfa4334d7198f483a92cd45f83493a5b2342be8c5dfa27ec`.
The complete witnesses include six items, four ordinary data items plus
script and control block, with zero hints and no annex.

| Funded case | Local consensus / policy profiles | Core block / mempool | Complete witness bytes |
| --- | --- | --- | ---: |
| Byte equality, positive and negative extremes (two spends) | Accept / Accept | Accept / Accept | 62 each |
| Byte equality, unequal positive wide sums | Reject / Reject | Reject / Reject | 62 |
| Byte equality, negative-zero input alias | Accept / Reject | Accept / Reject | 47 |
| Carry limbs, positive and negative extremes (two spends) | Accept / Accept | Accept / Accept | 296 each |
| Numeric equality, positive wide sums | Reject / Reject | Reject / Reject | 62 |
| Numeric equality, negative wide sums | Accept / Accept | Reject / Reject | 62 |

The exact accepted extreme spends for the two working schedules are
`differentially-validated` and `policy-validated`. The negative-zero fixture
is `differentially-validated` and `consensus-validated`. The local
interpreter's computed-number upper-bound check omits the corresponding
negative bound. Five-byte witness numbers still reject as inputs. The
[negative result](../negative-results/scriptnum-wide-sum.md) separates the
known local discrepancy from the Core verdict and the byte comparator.

## Reproduction

```sh
cargo test --locked --lib arithmetic::sum_equality::tests
cargo test --locked --test primitive_metrics scriptnum_equal_sums_metrics_are_current
python3 tools/scriptnum_equal_sums_regtest.py --download-core
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The unit suite checks both schedules against an independent Rust `i64` oracle
on all 14,641 combinations from an 11-value boundary grid. It checks hostile
encodings at every operand, short and surplus witnesses, and observable
caller state at 1,000 items and one beyond. The generator derives complete
witnesses from the same policy-compiled bytes as local execution. The
compiler and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
See the [implementation README](../../src/arithmetic/scriptint/README.md#exact-equality-of-two-signed-sums)
and catalog `arithmetic/scriptnum-equal-sums`.
