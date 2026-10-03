# CRC-8/SMBus over numeric nibbles

`crc8_smbus_nibbles(byte_count)` computes an eight-bit, noncryptographic checksum
of a complete byte message represented by hostile numeric nibbles. Four-bit
feedback uses a sixteen-entry remainder table and the existing triangular XOR
lookup. It returns one canonical ScriptNum and preserves older caller bytes on
both stacks. The fixed checksum is not message authentication.

## Parameters

- `byte_count`: 0..=406, no default; constructors reject 407 and u32::MAX before
  doubling the input count. `CRC8_SMBUS_MAX_BYTES` is 406.
- Polynomial: `x^8+x^2+x+1` (`0x07` without the leading coefficient).
- Initial register: zero. MSB-first input, no reflection, no final xor.
- Representation: two numeric nibbles per byte, high nibble first; the first
  logical nibble is at the top of the entry stack. This API admits complete
  bytes, unlike the private half-byte transition probe.
- Encoding: at most four-byte ScriptNums in 0..=15; numeric aliases and negative
  zero are accepted when the profile permits them. Output is canonical in
  0..=255, so a CRC >=128 uses two ScriptNum bytes, not a raw byte.

## Script metrics

Fragment includes numeric guards, 184 resident table items, CRC state, every
query, canonical packing and cleanup. Input pushes and terminal checks are
excluded. Leaf additionally compares the exact checksum then returns TRUE.
Witness bytes serialize the complete data vector with CompactSize prefixes,
excluding leaf/control block/annex/transaction. All data coexist at entry;
every row has **0 (none) hint items and zero hint bytes**.

| Configuration | Fragment | Checked leaf | Witness | Ordinary data / hints | Combined peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Empty message | 1 | 1 | 1 | 0 / 0 | 1 |
| One byte, varied | <!-- metric:crc8_smbus1 -->414<!-- /metric:crc8_smbus1 --> | 419 | 5 | 2 / 0 | 190 |
| Two bytes, varied | <!-- metric:crc8_smbus2 -->520<!-- /metric:crc8_smbus2 --> | 524 | 9 | 4 / 0 | 192 |
| Nine bytes, ASCII `123456789` | <!-- metric:crc8_smbus9 -->1262<!-- /metric:crc8_smbus9 --> | <!-- metric:crc8_smbus9_leaf -->1267<!-- /metric:crc8_smbus9_leaf --> | <!-- metric:crc8_smbus9_witness -->37<!-- /metric:crc8_smbus9_witness --> | 18 / 0 | <!-- metric:crc8_smbus9_stack -->206<!-- /metric:crc8_smbus9_stack --> |
| 306 bytes, varied | 32,744 | 32,749 | 1,189 | 612 / 0 | 800 |
| 307 bytes, varied | 32,851 | 32,856 | 1,193 | 614 / 0 | 802 |
| 406 bytes, varied | <!-- metric:crc8_smbus406 -->43345<!-- /metric:crc8_smbus406 --> | 43,349 | 1,576 | 812 / 0 | 1,000 |

One/two/nine/306-byte rows use ALL; 307 and 406 use NONE and are explicitly
unoptimized. Final options are chosen independently for each whole fragment
and leaf. Nine bytes has <!-- metric:crc8_smbus9_static -->787<!-- /metric:crc8_smbus9_static -->
static non-push opcodes. Executed counts and a complete validation budget are
unknown, recorded as null. Zero charged signature weight is not budget evidence.

The matched serial bit-register baseline is smaller at one byte (285 versus
414), but larger at two (541 versus 520) and nine (2,333 versus 1,262). Its
combined peak is N+13 rather than N+188, and it supports more all-entry data.
These comparisons include identical numeric domains, witnesses, setup, cleanup,
packing and terminal predicates. [NR-081](../../../../knowledge/negative-results/crc8-nibble-feedback.md)
retains startup and memory tradeoffs. Canonical-input compositions are separate
measured families, built using the existing `verify_canonical_nibble` helper.

For nine-byte independent messages, two invocations use fragment/leaf
2,524/2,532, witness 71, 36 ordinary data / zero total or incremental hints,
and peak 224. Eight use 10,096/10,126, witness 280, 144 data / zero hints,
peak 332. Twenty-five use 31,550/31,638 with ALL; twenty-six use
32,890/32,982 with unoptimized NONE. Individually ALL-compiled components plus
park/restore sum to 31,600/32,864; whole-policy deltas are -50/+26. The latter
includes the change to NONE, not merely loss of cross-component rewrites.
At 45, fragment/leaf 56,925/57,083 are unoptimized NONE, witness 1,573,
810 data / zero hints, peak 998. Two caller items fit; three do not. At 46,
828 ordinary data / zero hints overflow at measured peak 1,001.

## Security

CRC-8 is linear and has only 256 outputs; deliberate collisions are easy.
No cryptographic authentication, preimage or collision security is claimed.
The caller authenticates input provenance and binds the expected CRC when
needed. CRC equality does not bind message bytes or raw witness encodings.
Numeric guards reject hostile indices before any lookup; table contents are
embedded, never supplied by witnesses. A zero CRC is valid data but a false
bare predicate; the caller supplies the complete terminal/clean-stack condition.

## Script compatibility and standardness

- Bare legacy: uses existing enabled opcodes, but the two-byte fragment's 255
  static non-push opcodes already exceed the 201-opcode legacy limit. Smaller
  configurations have no local legacy consensus validation.
- P2SH: also subject to the 520-byte redeem-script item bound; the two-byte
  checked leaf is 524 bytes. No P2SH validity or policy acceptance is established.
- P2WSH: retains the legacy opcode limit and other resource/policy rules. The
  nine-byte checked leaf has 787+1 static non-push opcodes, above that limit.
- Tapscript: locally exercised with combined stack enforcement and MINIMALIF,
  numeric minimality off, OP_CAT off, CLTV/CSV on, synthetic empty transaction,
  data-only budget and no signatures. Policy controls add minimality and the
  80-byte entry-item cap, a subset of relay rules. Every published configuration
  remains `locally-reproduced` / `unclassified`; there is no CRC Core or complete
  transaction/policy validation. See [script types](../../../../docs/script-types.md)
  and [standardness](../../../../docs/standardness.md).

## Witness and hints

For bytes `m[0]..m[B-1]`, entry main is
`caller | low(last) | high(last) | ... | low(0) | high(0)`.
There are 2B ordinary public input items and zero mandatory or optional hints.
All are present at entry. Numeric four-byte aliases can encode the same fixture
and attain a complete Consensus witness maximum of `5*(2B)+CompactSize(2B)`
bytes: 91 at nine bytes and 4,063 at 406. Partial Policy rejects those aliases.
Canonical siblings have a domain encoding bound `2*(2B)+CompactSize(2B)`;
their exact maximum subject to the bound checksum is not established, so report
maximum fields are null. Serialized hint bytes never substitute for item counts.

Repeated calls retain every future message and each produced CRC. The repeated
wrapper consumes messages top first and returns canonical CRCs top first. All
18R ordinary data items are at entry, with zero incremental and zero total hint
items. Numeric witness maxima at R=2/8/25/26/45 are 181/721/2,253/2,343/4,053.
Both caller stacks and parked outputs count toward the 1,000-item limit.

## Stack contract

Consumes exactly the declared input nibbles and returns one canonical numeric
CRC. Older main/alt data survive, including opaque nonnumeric bytes. Nonempty
combined peak is `2B+188+caller_main+caller_alt`; 184 embedded table items,
two CRC nibbles and temporary guards/sort/query state account for the overhead.
Cleanup removes every table and leaves no temporary alt items. Empty input
returns zero and needs one result item, plus caller state. A fragment is not a
complete locking script; callers bind the checksum and satisfy clean stack.

## Operational notes

The initial prototype is preserved at immutable source
`0db90b9450d96a0bdf292d633fff14036bac2745` before production changes. Four shared
families cover exhaustive two-byte messages, original bytecode parity,
boundaries, malformed/alias/short inputs at every live position, asymmetric
order, all outputs, runtime caller bytes and exact limits. Compiled range,
canonicality and terminal bypasses retain valid controls and are caught by
the same typed assertions; ordering mutations are caught by the same exact
result assertion. All measured repetitions audit every hostile position and
short prefix, across both sides of the compilation cutoff.

Independent bitwise Python CRC checks validate the final scalar/composition
artifacts against the Rust polynomial-division oracle, source hashes, witness
serialization and actual Cargo identities. Reproduce with
[research commands](../../../../research/crc8-nibble-feedback/README.md).
Deterministic input patterns and all compiler/interpreter/profile/hash pins
are in [metrics.json](../../../../research/crc8-nibble-feedback/metrics.json).
The constructor deliberately has no automatic small-message dispatcher.

## Knowledge-base integration

- [Primitive](../../../../knowledge/primitives/crc8-smbus.md), catalog ID
  `arithmetic/crc8-smbus`.
- [Arithmetic comparison](../../../../knowledge/comparisons/arithmetic.md),
  [lookup comparison](../../../../knowledge/comparisons/lookup-strategies.md),
  [composition](../../../../knowledge/techniques/composition.md).
- [NR-081](../../../../knowledge/negative-results/crc8-nibble-feedback.md) and
  [OP-039](../../../../knowledge/open-problems.md#op-039--streamed-crc-8-frontier).
- Primary polynomial/order reference: [SMBus v3.1, section 6.4.1.3](https://smbus.org/specs/SMBus_3_1_20180319.pdf).
  Independent algorithm context: [Linux v6.18 crc8 at immutable source](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/lib/crc/crc8.c).
