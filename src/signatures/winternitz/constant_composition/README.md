# Constant-composition Winternitz for 20-byte messages

A terminal verifier that publishes an unchanged 20-byte message using a
reversible assignment of a fixed multiset of digits to independent hash chains.
The smallest HASH160 fragment is **1,598 bytes** with an attained **802-byte**
maximum signer witness: **2,400 bytes combined**, down from the previous
constant-sum profile's 3,624. The composable variant totals **2,498 bytes**.
These are custom experimental one-time signatures, not WOTS+.

## Parameters and encoding

`ConstantCompositionWinternitz20<H = Hash160, P = Preimage16>` fixes the
message length to 20 bytes, radix to **25**, and number of independent keys to
**49**. The digit multiplicities are:

| Digit | Multiplicity per digit | Keys in group |
| --- | ---: | ---: |
| 0 through 14 | 1 | 15 |
| 15 through 21 | 2 | 14 |
| 22 through 23 | 3 | 6 |
| 24 | 14 | 14 |

All assignments have sum 828, but the verifier enforces the stronger condition
that the entire composition is fixed. The number of distinct assignments is

```text
49! / (2!^7 * 3!^2 * 14!)
= 1514202802528191317310959056853549737574400000000
> 2^160
```

Interpret the original 20 bytes as a big-endian integer. Exact multinomial
unranking maps it to the corresponding lexicographic assignment, in original
key-index order. Ranking is its inverse. This preserves **all 160 message
bits**: there is no hashing of the message, padding search, or message grinding.
The available capacity is approximately 160.0511 bits. Script accepts the full
composition, while host decoding rejects the unused suffix with rank at least
`2^160`. A protocol must define how it handles that suffix.

The digit geometry is fixed by this implementation. The bounded parameter
search in [`tests/search.rs`](tests/search.rs) found it for the HASH160 objective;
it does not establish global optimality. Hash choices are `Hash160`, `Sha256`,
and `Sha256Hash160`. Start modes are `Preimage16` (default) and `FullWidth`.
See [shared definitions](../shared/README.md) for exact chain and commitment
semantics. Only initial secrets are shortened; later openings retain the
20-byte or 32-byte native width.

Multiset capacity follows [NIST DLMF §26.16](https://dlmf.nist.gov/26.16),
version 1.2.7 (2026-06-15). Fixed-sum antichains are established in
[ePrint 2023/850](https://eprint.iacr.org/2023/850), received 2023-06-06.
Those sources do not prove this custom Script verifier's cryptographic security.

## How fixed composition reduces both costs

An opening for digit `d` is the node after `d` hashes; its endpoint is after
24 hashes. Present the **35 nonmaximum openings in ascending digit order**.
Their verification hash counts are then compile-time constants. There is no
per-chain digit lookup table, branch ladder, numeric sum, or checksum chain.
The fourteen unselected trusted keys fill the maximum-digit group implicitly
and need no opening.

The verifier stages the signature on the altstack, then loads all 49 independent
public commitments into a main-stack pool. A selector uses `OP_ROLL` to remove
its chosen key permanently. It then verifies the slot's node against that key.
This destructive selection enforces uniqueness without a separate bitmap or
pairwise distinctness checks. The fourteen remaining keys fill the implicit
maximum-digit slots and are dropped.

Every valid signature performs 348 native chain-hash steps before compilation.
The centralized compiler fuses SHA-256 pairs into `OP_HASH256` where applicable;
reported sizes and static opcode counts use the resulting whole fragment.
HASH160's composable 1,696-byte breakdown is 1,029 bytes of public-key pushes,
70 staging opcodes, 242 bytes of selector routing/comparison, 348 hash opcodes,
and seven cleanup opcodes. The isolated fragment replaces 102 bytes of clamps
with a four-byte entry-depth check, giving 1,598 bytes. There is no residual
cross-component optimization delta for this HASH160 breakdown.

## Witness and stack contract

`to_witness()` serializes chunks in forward slot order:

```text
[selector_0, node_0, selector_1, node_1, ..., selector_34, node_34]
```

Within an equal-digit group, the signer orders original key indices ascending.
A selector is the chosen key's zero-based position in the remaining pool,
whose keys are sorted by original index. Signer selectors are minimal
ScriptNums, from 0 through 48 initially and 0 through 14 finally. The full
signature assignment is recoverable offchain from these selections; the
fourteen unselected keys have digit 24.

There are **70 signature data items**: 35 selectors and 35 nodes, and
**0 auxiliary hint items (0 hint bytes)** per invocation. All 70 coexist at
entry. The node count includes exactly one 16-byte initial secret and 34 native
nodes under `Preimage16`. Selectors are mandatory signature data, not optional
acceleration hints. Embedded public keys are script data, not witness items.

All methods consume the signature and leave **no result**. The caller must
append its terminal predicate. These are distinct contracts:

| Method | Entry main stack | Selector validation | Unrelated state |
| --- | --- | --- | --- |
| `checksig_verify_isolated_and_clear` | Exactly the 70 signature items | Checks entry depth; subsequent `OP_ROLL` is confined to the entire trusted pool | Preserves altstack state; rejects extra main-stack items |
| `checksig_verify_and_clear` | Any state below the 70 items | Upper-clamps each selector to the last remaining key | Preserves main and altstack state |
| `checksig_verify_bounded_and_clear` | Any state below the 70 items | Explicitly rejects selectors at or above pool size | Preserves main and altstack state |

Negative and over-four-byte ScriptNums fail. The clamped mode admits positive
selector aliases for the last pool key. Equal-digit reorderings may also encode
the same assignment. Neither changes the authenticated message; these APIs do
not promise strong unforgeability or a unique raw witness. No method checks raw
node widths: every explicit opening is hashed at least once.

The isolated fragment peaks at **119** combined main/altstack items; the
composable clamped and bounded variants peak at **120** and **121** respectively,
plus any surrounding state. These peaks include the simultaneously staged
signature, the trusted key pool, and validation temporaries. For repeated calls,
each signature still has 70 data items and zero auxiliary hints. If `k`
signatures coexist at entry, there are `70*k` data items; an isolated fragment
cannot run with the other signatures underneath it on the main stack. Schedule
fragments or stage surrounding data explicitly, and count all live main and
altstack state against the same 1,000-item limit. No batched cost is measured.

## Security and BitVM3 integration

For honest independent keys, changing a key-to-digit assignment while preserving
its multiset must decrease at least one key's digit. Producing that earlier
opening requires chain inversion or a hash collision under the assumed hash
properties. `OP_ROLL` prevents reusing one favorable key for multiple slots;
all three methods confine selection to trusted public keys. The implicit
maximum slots fit the same fixed-composition argument. This is a local security
argument, not a formal reduction for this custom unkeyed construction.

Each key must sign **only one message**. Consuming the Rust signing key does not
prevent seed restoration, rollback, or concurrent reuse. Derivation includes a
new construction namespace, the hash profile, preimage mode, and complete
composition; signatures are incompatible with the other Winternitz encodings.
All 49 chains must be independently derived. Sharing an endpoint or reusing
chain secrets can destroy the argument.

Sixteen-byte starts impose a 128-bit single-target exhaustive-search ceiling
before multi-target losses. HASH160 and hybrid endpoint commitments have an
80-bit generic collision bound; SHA-256 has a 128-bit bound. Short secrets do
not imply 128-bit collision resistance for HASH160. These are generic bounds,
not concrete end-to-end security estimates. See [shared security](../shared/README.md).

**BitVM3 can handle constant-sum representations**, including the stronger
constant-composition encoding used here, without requiring the publication
script to recover the original proof bytes. The protocol must bind this
encoding, key namespace, and invalid-rank behavior to its proof interpretation.
This implementation verifies and consumes the assignment; it is not a complete
BitVM3 protocol validation. A different consumer that needs the original bytes
inside Script must include a decoder in its comparison.

## Cost boundary and reproduction

The [first overview table](../README.md#total-onchain-cost-for-20-byte-terminal-verification)
contains policy-compiled fragment sizes, varied-message witnesses, and attained
maximum signer witnesses. Fragments include commitments, all checks and cleanup.
Witness bytes include their item count and every length prefix. The terminal
predicate, script-item framing, control block, and other transaction bytes are
excluded equally from all profiles. No input pushes substitute for witness data.

For HASH160/Preimage16, the maximum witness is exactly
`1 + 35*2 + 17 + 34*21 = 802` bytes. It is attained by the valid message
`bd736e13851a9581860e655a5f31f6d5e4000000`: key 0 has implicit digit 24, so all
explicit selectors are nonzero. This bound covers signer-produced witnesses,
not arbitrary raw aliases. The varied fixture is byte `i = (37*i) mod 256`;
all measured keys derive from seed `[0x42;32]`.

Independent exact aggregation over all `2^160` message ranks gives the witness
mean `279002050908463561453381360222397559584207713 /
348449143727040986586495598010130648530944`, approximately **800.696617946121**
bytes. Mean totals are **2,398.70** isolated and **2,496.70** composable. These
are uniform-message expectations, not sampled estimates. Hybrid and SHA-256
increase every Preimage16 witness by 408 bytes for the same assignment;
FullWidth adds four bytes for HASH160 or sixteen bytes for SHA-256/hybrid.

Metrics are `locally-reproduced`, `research-unlimited`: the repository metric
helper runs tapscript with stack-limit checking disabled. Separate strict local
execution tests are `unclassified` for deployment. Static non-push counts below
are measured from the compiled fragment; there are no runtime branches, so a
successful invocation executes each of those non-push opcodes once. Total
executed-opcode and validation-budget counters are not recorded.

The fragment measurements used `rust-bitcoin-script` commit
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and `bitcoin-scriptexec` commit
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1`. That executor had an off-by-one
`OP_ROLL` bounds bug: a positive index equal to the pool length could panic in
the isolated mode. The original focused test recorded this harness limitation.
[Bitcoin Core v29.0 rejects that boundary](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp#L757-L784).
The composable modes prevent that index reaching `OP_ROLL`. Source inspection
is distinct from the later [v30.3 differential run](../../../../knowledge/core-validation.md),
which confirms that exact boundary is rejected by Core.
The lab now pins repaired interpreter `4b7269a`, including the selector-bound,
resource-limit and executed-push-minimality fixes; see
[adoption and scope](../../../../knowledge/negative-results/index.md#nr-048-minimal-push-policy-must-follow-execution).
The historical metrics and reports retain their original tool provenance and
evidence classes.

## Script compatibility and standardness

The native hashes and stack operators are enabled in bare Script, P2SH, P2WSH,
and tapscript, but every measured fragment exceeds the legacy/Segwit-v0 limit
of 201 counted non-push opcodes. Thus bare/P2SH/P2WSH deployment is
`consensus-incompatible` for these fragments; P2SH also cannot push a redeem
script of this size as one <=520-byte element. Tapscript removes that opcode
limit. A separate deterministic isolated HASH160/Preimage16 complete leaf is
now `differentially-validated` and `policy-validated` by Core v30.3: 1,599 script
bytes including `OP_TRUE`, 796 data-witness bytes, 2,432 full Taproot witness
bytes, and 2,810 WU / 703 vbytes for the one-input, one-output spend. Its 70
signature data items coexist at entry, with zero hints and a stack-limited
local combined peak of 119. The full witness includes script/control block.
This is the varied-message fixture only; the existing fragment snapshots,
other profiles and full protocol integrations retain their prior evidence.
The [recorded report](../../../../tests/data/core-validation-v30.3.json) also
separates consensus-valid nonminimal selectors from policy rejection.
See [script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Operational notes and tests

[`mod.rs`](mod.rs) contains the encoder, keys, signer and three verifier methods.
The tests under [`tests/`](tests/) cover encoder boundaries, deterministic
roundtrips, unused ranks, all hash/start modes, malformed selectors and nodes,
forwarding attacks, duplicate-key attempts, witness aliases, cleanup and
preservation of caller state. Independent Python uses only its standard library
and does not import Rust. Search is a standalone Rust program with finite,
documented bounds and floating-point screening followed by exact capacity checks.

```sh
python3 tools/core_regtest.py --download-core
cargo test --locked signatures::winternitz::constant_composition
cargo test --locked --test primitive_metrics winternitz20_composition_metrics_are_current
python3 src/signatures/winternitz/constant_composition/tests/vectors.py
rustc -O src/signatures/winternitz/constant_composition/tests/search.rs -o /tmp/winternitz-composition-search
/tmp/winternitz-composition-search
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Only intentionally changed metrics should be refreshed with
`UPDATE_PRIMITIVE_METRICS=1`; normal runs check them. See the
[knowledge record](../../../../knowledge/primitives/winternitz-constant-composition20.md),
[signature comparison](../../../../knowledge/comparisons/signatures.md),
[negative results](../../../../knowledge/negative-results/index.md#nr-042-constant-composition-search-and-endpoint-sharing-limits),
and [OP-009](../../../../knowledge/open-problems.md#op-009--one-time-authentication-security-profiles).

## Detailed metric snapshots

Summary script and witness sizes are in the [first overview table](../README.md#total-onchain-cost-for-20-byte-terminal-verification).

| Profile | Entry data items | Auxiliary hints | Combined stack peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| Constant-composition HASH160, isolated | <!-- metric:w20_composition_isolated_hash160_items -->70<!-- /metric:w20_composition_isolated_hash160_items --> | <!-- metric:w20_composition_isolated_hash160_hints -->0<!-- /metric:w20_composition_isolated_hash160_hints --> | <!-- metric:w20_composition_isolated_hash160_stack -->119<!-- /metric:w20_composition_isolated_hash160_stack --> | <!-- metric:w20_composition_isolated_hash160_opcodes -->567<!-- /metric:w20_composition_isolated_hash160_opcodes --> |
| Constant-composition HASH160, composable | <!-- metric:w20_composition_clamped_hash160_items -->70<!-- /metric:w20_composition_clamped_hash160_items --> | <!-- metric:w20_composition_clamped_hash160_hints -->0<!-- /metric:w20_composition_clamped_hash160_hints --> | <!-- metric:w20_composition_clamped_hash160_stack -->120<!-- /metric:w20_composition_clamped_hash160_stack --> | <!-- metric:w20_composition_clamped_hash160_opcodes -->600<!-- /metric:w20_composition_clamped_hash160_opcodes --> |
| Constant-composition HASH160, bounded | <!-- metric:w20_composition_bounded_hash160_items -->70<!-- /metric:w20_composition_bounded_hash160_items --> | <!-- metric:w20_composition_bounded_hash160_hints -->0<!-- /metric:w20_composition_bounded_hash160_hints --> | <!-- metric:w20_composition_bounded_hash160_stack -->121<!-- /metric:w20_composition_bounded_hash160_stack --> | <!-- metric:w20_composition_bounded_hash160_opcodes -->670<!-- /metric:w20_composition_bounded_hash160_opcodes --> |
| Constant-composition hybrid, isolated | <!-- metric:w20_composition_isolated_hybrid_items -->70<!-- /metric:w20_composition_isolated_hybrid_items --> | <!-- metric:w20_composition_isolated_hybrid_hints -->0<!-- /metric:w20_composition_isolated_hybrid_hints --> | <!-- metric:w20_composition_isolated_hybrid_stack -->119<!-- /metric:w20_composition_isolated_hybrid_stack --> | <!-- metric:w20_composition_isolated_hybrid_opcodes -->437<!-- /metric:w20_composition_isolated_hybrid_opcodes --> |
| Constant-composition SHA-256, isolated | <!-- metric:w20_composition_isolated_sha256_items -->70<!-- /metric:w20_composition_isolated_sha256_items --> | <!-- metric:w20_composition_isolated_sha256_hints -->0<!-- /metric:w20_composition_isolated_sha256_hints --> | <!-- metric:w20_composition_isolated_sha256_stack -->119<!-- /metric:w20_composition_isolated_sha256_stack --> | <!-- metric:w20_composition_isolated_sha256_opcodes -->402<!-- /metric:w20_composition_isolated_sha256_opcodes --> |

<details>
<summary>Boundary regression fixtures (not representative message comparisons)</summary>

| Profile | Zero witness | All-ff witness |
| --- | ---: | ---: |
| Constant-composition HASH160, isolated | <!-- metric:w20_composition_isolated_hash160_witness_zero -->767<!-- /metric:w20_composition_isolated_hash160_witness_zero --> | <!-- metric:w20_composition_isolated_hash160_witness_ff -->802<!-- /metric:w20_composition_isolated_hash160_witness_ff --> |
| Constant-composition HASH160, composable | <!-- metric:w20_composition_clamped_hash160_witness_zero -->767<!-- /metric:w20_composition_clamped_hash160_witness_zero --> | <!-- metric:w20_composition_clamped_hash160_witness_ff -->802<!-- /metric:w20_composition_clamped_hash160_witness_ff --> |
| Constant-composition HASH160, bounded | <!-- metric:w20_composition_bounded_hash160_witness_zero -->767<!-- /metric:w20_composition_bounded_hash160_witness_zero --> | <!-- metric:w20_composition_bounded_hash160_witness_ff -->802<!-- /metric:w20_composition_bounded_hash160_witness_ff --> |
| Constant-composition hybrid, isolated | <!-- metric:w20_composition_isolated_hybrid_witness_zero -->1175<!-- /metric:w20_composition_isolated_hybrid_witness_zero --> | <!-- metric:w20_composition_isolated_hybrid_witness_ff -->1210<!-- /metric:w20_composition_isolated_hybrid_witness_ff --> |
| Constant-composition SHA-256, isolated | <!-- metric:w20_composition_isolated_sha256_witness_zero -->1175<!-- /metric:w20_composition_isolated_sha256_witness_zero --> | <!-- metric:w20_composition_isolated_sha256_witness_ff -->1210<!-- /metric:w20_composition_isolated_sha256_witness_ff --> |

</details>
