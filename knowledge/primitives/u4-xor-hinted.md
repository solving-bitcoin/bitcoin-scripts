# Parity-hinted XOR reduction

## Research question and hypothesis

XOR is bitwise parity, but Script has no bitwise opcodes, so the repository's XOR
reduction walks a resident 256-entry table (about 24 script bytes per nibble plus a
380-byte fixed table cost and a 256-item stack peak). Can an XOR be verified from a
claimed result using exact integer arithmetic? The hypothesis is that per-bit counts
packed in non-carrying lanes, plus a claimed half-count per lane, check the parity
of every bit at once without the table. This is a new local construction; no global
novelty claim is made for lane packing or parity certificates.

## Contract and proof

`arithmetic::u4::xor_hinted::u4_nibbles_xor_hinted(n)`, `1 <= n <= 212`:

```text
witness: x[0..n-1] | y | h0 h1 h2 h3     ->     y
```

Let `B = n + 2` and `T[v] = sum_{b<4} bit_b(v) * B^b`. The script range-checks every
`h_b` to `0..=n/2` and every nibble and `y` to `0..=15`, then requires
`S = sum_i T[x_i]` to equal `T[y] + 2 * H` where `H = sum_b h_b * B^b`. Lane `b` of
`S` is `c_b`, the number of nibbles with bit `b` set, at most `n < B`. Lane `b` of the
right side is `y_b + 2 h_b <= 1 + n < B`. Both sides are therefore base-`B`
numbers with every digit below `B`, so equal integers have equal digits:
`c_b = y_b + 2 h_b`, i.e. `y_b` is `c_b mod 2`, the XOR bit. A forged `y` or `h`
cannot pass, and the honest numeric pair is unique. All sums are below `2^31` for
`n <= 212`, where `n * (B^4 - 1) / (B - 1)` stays inside the four-byte domain.

## Threat model and evidence

Nibbles, the claim and the lane halves are hostile. Tests cover: honest hints for every
vector of one to three nibbles; an **exhaustive hint search** over `y` in `-1..=16` and
all four half-counts in `-1..=3` (11,250 candidate tuples) for the vectors `[9, 5]`,
`[15, 15, 15]`, `[0, 0]` and `[3, 12, 6, 6]`, where exactly one tuple, the honest
one, verifies; seeded vectors up to 212 nibbles against the table reduction, and
the all-fifteen worst case; out-of-range nibbles, claims (`-1`, 16, 255) and
halves; preserved main/alt state; generation bounds; and a check that the
accumulator bound fits at the limit. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded. Sizes pinned by `xor_hinted::tests::recorded_sizes_are_current`.

| n | Table script bytes | Hinted script bytes |
| ---: | ---: | ---: |
| 4 | 464 | 175 |
| 16 | 740 | 367 |
| 32 | 1,122 | 617 |
| 64 | 1,890 | 1,087 |
| 212 | 5,525 | 3,378 |

Only the 32-item fixture has pinned witness and peak measurements in this comparison: table 63 witness bytes and peak 289, hinted 72 bytes and peak 59. Non-32 witness and peak figures are not asserted here.
The hinted form is 50% smaller on script at 16 nibbles and 42% at 64, with five hint
items and, in the 32-item fixture, a 59-item rather than 289-item peak because it
needs no resident table. The implementation cap of 212 is deliberately conservative: at 213 the bound is 2,126,765,808 and still fits; the bound first exceeds the domain at 214. Supporting 213 requires separate implementation and execution testing.

## Reproduction

```sh
cargo test --locked arithmetic::u4::xor_hinted::tests --lib
cargo test --locked --test primitive_metrics u4_xor_hinted_metrics_are_current -- --exact
python3 tools/kb.py validate
```

For the 32-item fixture the five hints add 9 serialized bytes to the existing witness; a separately serialized hint vector occupies 10 bytes, including its item count.

The verifier binds numeric values; it returns the original y bytes, so padded
numbers and negative zero can pass without MINIMALDATA. Byte-sensitive consumers
must canonicalize. Each invocation has five hints and n input items, all
coexisting at entry; k equal-width preloaded invocations therefore start with
k(n+5) data items including 5k hints, before caller state and transient work.
The isolated hinted peak is n+27; any batch must also allow for remaining items,
caller main/alt state and routing overhead under the 1,000-item limit. No batch
schedule or peak is measured. The 32-item 617-byte fragment exceeds P2SH's
520-byte element limit, and its 383 non-push opcodes exceed the legacy, P2SH and
P2WSH 201-opcode limit; tapscript removes that opcode limit. No consensus or
policy validation is claimed. The peak metric runs a checking leaf with the
explicit local consensus numeric profile, while bytes/opcodes cover the fragment.

For the measured 32-item configurations, both the 617-byte hinted fragment and the 1,122-byte table fragment exceed P2SH’s 520-byte redeem-script element limit; their 383 and 758 non-push opcodes exceed the 201-opcode legacy, P2SH and P2WSH limit. Tapscript removes that opcode limit but retains stack and element constraints. Complete-script and relay-policy validity have not been established.
