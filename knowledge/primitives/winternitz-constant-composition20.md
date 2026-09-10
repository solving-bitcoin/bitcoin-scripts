# Constant-composition Winternitz for 20-byte messages

This experimental terminal construction verifies an unchanged 20-byte message
through a reversible fixed-composition encoding. Its HASH160/Preimage16 profile
uses **1,598 script bytes + 802 maximum signer-witness bytes = 2,400 bytes**
when the signature occupies the entire main stack. Preserving unrelated main
state costs **2,498 bytes**. These improve the previous constant-sum maximum
of 3,624 bytes by 33.8% and 31.1%, respectively.

The catalog ID is `signature/winternitz-constant-composition20`. Implementation,
precise contracts and regression markers are in the
[construction README](../../src/signatures/winternitz/constant_composition/README.md).
The [overview's first table](../../src/signatures/winternitz/README.md#total-onchain-cost-for-20-byte-terminal-verification)
compares all three constructions on the same terminal boundary.

## Construction and evidence

There are 49 independent chains with radix 25. Digits 0–14 occur once each,
15–21 twice each, 22–23 three times each, and 24 fourteen times. The capacity
is `49! / (2!^7 * 3!^2 * 14!)`, exactly
`1514202802528191317310959056853549737574400000000 > 2^160`.
Interpret the original bytes as a big-endian rank and select the corresponding
lexicographic assignment. Exact ranking reverses that mapping; no message
alteration, padding search, or grinding is involved. This is a constant-sum
code with the stronger restriction of fixed symbol multiplicities.

The signer orders 35 openings by increasing digit. Their hash counts are fixed
at compilation. A shrinking pool of trusted public keys is consumed with
`OP_ROLL`, enforcing that every opening chooses a different key. The fourteen
unselected keys receive the maximum digit implicitly and need no witness items.
There are no checksum chains, dynamic chain-depth tables, or sum accumulators.
All valid signatures require 348 native chain steps before SHA-256-pair fusion.

The isolated fragment checks entry depth once so that its key pool is the
entire main stack; intrinsic `OP_ROLL` bounds then protect all lookups. The
composable clamped fragment instead clamps each index within the remaining
pool; the bounded variant explicitly rejects upper aliases. All enforce the
fixed composition. Host decoding additionally enforces rank `<2^160`; the
Script fragments do not reject the small unused rank suffix.

Multiset counting is `reported` by source `nist-dlmf-multiset-permutations`,
[NIST DLMF §26.16](https://dlmf.nist.gov/26.16), version 1.2.7, released
2026-06-15. The established constant-sum approach is `reported` by
`constant-sum-wots-2023`, [ePrint 2023/850](https://eprint.iacr.org/2023/850),
received 2023-06-06. The Script key pool, parameter selection and byte savings
are local results. Neither source supplies a cryptographic proof for this
custom unkeyed construction.

## Comparable measurements

Seed `[0x42;32]`, Preimage16, policy-produced fragment, complete serialized
signature witness. Script includes all commitments, checks and cleanup;
terminal predicate, script framing, control block and transaction overhead are
excluded equally. The varied message has byte `i = (37*i) mod 256`.

| Profile | Script | Varied witness | Maximum signer witness | Maximum total | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HASH160 isolated | 1,598 | 796 | 802 | 2,400 | 119 | 567 |
| HASH160 composable clamped | 1,696 | 796 | 802 | 2,498 | 120 | 600 |
| HASH160 composable bounded | 1,767 | 796 | 802 | 2,569 | 121 | 670 |
| SHA-256/HASH160 isolated | 1,468 | 1,204 | 1,210 | 2,678 | 119 | 437 |
| SHA-256 isolated | 2,021 | 1,204 | 1,210 | 3,231 | 119 | 402 |

Each invocation has **70 signature data items** (35 selectors, 35 nodes),
**zero auxiliary hints**, with all items present at entry. Public commitments
are embedded in Script. Peaks include both stacks, staged signature, key pool,
and temporaries. Composable variants preserve unrelated main/alt state;
isolated preserves alt state but rejects extra main items. Every fragment
leaves no result. Surrounding live state counts toward the same 1,000-item
limit; no batched metric is reported.

The maximum is attained inside the actual encoder image by message
`bd736e13851a9581860e655a5f31f6d5e4000000`. Exact counting over all `2^160`
messages gives a HASH160 mean witness of approximately 800.696617946121 bytes,
with totals 2,398.696617946121 isolated and 2,496.696617946121 composable.
These are exact rational aggregates displayed as rounded decimals, not samples.
All bounds concern signer-produced witnesses rather than arbitrary raw aliases.

Measurements are `locally-reproduced`, `research-unlimited`: the metric helper
uses tapscript and disables the stack limit. Separate strict local tests are
`unclassified` for deployment. The historical `ba96bc2` executor panicked for
an isolated `OP_ROLL` index exactly equal to the pool length. Current integration
`4b7269a4` repairs that bug, and the boundary regression requires
`InvalidStackOperation` at all three tested slots while preserving the valid
control. The v30.3 [Core differential experiment](../core-validation.md)
confirms exact-bound rejection independently. Composable bounds prevent that malformed index reaching
`OP_ROLL`. Compilation uses
`bitcoin-script-locked`; the recorded fragment measurements retain
`bitcoin-scriptexec-locked` provenance. Current commands use the separately
documented repaired interpreter; historical evidence is not relabeled.

A separate complete-leaf configuration is `differentially-validated` and
`policy-validated` by Core v30.3 for the varied message: 1,599 locking bytes
including terminal `OP_TRUE`, 2,432 full Taproot witness bytes, and a one-input,
one-output spend of 2,810 WU / 703 vbytes. All 70 data items coexist at entry,
with zero hints and a local stack-limited combined peak of 119. The full witness
already includes the script and control block. This validates that exact
transaction, not the other hash profiles, composable variants or a full BitVM
protocol. Older fragment metrics retain their original evidence classes.

These enabled opcodes nevertheless exceed the 201-opcode limit for bare
Script, P2SH and P2WSH, making those script classes `consensus-incompatible`.
Tapscript removes that limit. Static counts are from compiled scripts; with
no runtime branches, each static non-push executes once on success. Separate
executed-opcode and validation-budget counters are not recorded.

## Security and protocol obligations

A different fixed-composition key assignment must decrease some original key's
digit. With honest independent key derivation, producing its earlier node
requires inversion or collision under the hash assumptions. Destructive
selection prevents duplicate use of a key. This local antichain argument does
not constitute a formal WOTS+ reduction. Sharing chain endpoints invalidates
the independent-coordinate argument.

Keys are strictly one-time; restore/reuse and concurrent-signing prevention
remain operational obligations. Initial secrets have 128-bit single-target
search space before multi-target effects. HASH160 and hybrid commitments retain
an 80-bit generic collision bound; pure SHA-256 has a 128-bit bound. All explicit
openings are hashed at least once, and raw node widths are not checked.
Selector aliases and equal-digit permutations need not produce unique witnesses.

BitVM3 can handle the reversible constant-sum representation, including this
fixed-composition subtype. A publication script need not reconstruct the
original SNARK proof bytes. A concrete integration must bind the encoding and
key namespace to proof interpretation and define unused-rank handling. A Script
consumer requiring recovered bytes must add the decoder's cost. No complete
BitVM3 transaction validation is included here.

Independent Python reproduces capacity, exact encoding, all six hash/start
profiles, serialized witness vectors, attained maximum and exact mean. Rust
covers malformed inputs, duplicate selections, forwarding, aliases, boundaries
and state preservation. The standalone bounded search retains failed/dominated
candidates; it is not a global minimum proof. See the
[reproduction commands](../../src/signatures/winternitz/constant_composition/README.md#operational-notes-and-tests),
[signature comparison](../comparisons/signatures.md),
[state transport](../protocols/one-time-state-transport.md),
[lookup pools](../techniques/lookup-tables.md),
[NR-042](../negative-results/index.md#nr-042-constant-composition-search-and-endpoint-sharing-limits),
and [OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).
