# Joint HASH160 and HASH256 preimage check

`commitments::dual_digest::verify_hash160_hash256` verifies that one raw
preimage opens two public digest constants. All witness bytes are hostile.
It computes the first SHA-256 once, then checks RIPEMD-160 and the second
SHA-256 of that intermediate.

## Parameters

The two public parameters are exact arrays of 20 and 32 bytes in hash output
order. Use `hash160::Hash::to_byte_array()` and
`sha256d::Hash::to_byte_array()` to obtain those arrays from rust-bitcoin.
There are no defaults.

## Script metrics

| Openings | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Peak | Executed non-push ops | Derived SHA-256 blocks | Derived RIPEMD-160 blocks |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Shared | <!-- metric:dual_digest_shared_one_script -->61<!-- /metric:dual_digest_shared_one_script --> | <!-- metric:dual_digest_shared_one_witness -->524<!-- /metric:dual_digest_shared_one_witness --> | 1 | 0 (none) | <!-- metric:dual_digest_shared_one_stack -->3<!-- /metric:dual_digest_shared_one_stack --> | <!-- metric:dual_digest_shared_one_executed -->6<!-- /metric:dual_digest_shared_one_executed --> | 10 | 1 |
| 1 | Separate native | <!-- metric:dual_digest_separate_one_script -->60<!-- /metric:dual_digest_separate_one_script --> | <!-- metric:dual_digest_separate_one_witness -->524<!-- /metric:dual_digest_separate_one_witness --> | 1 | 0 (none) | <!-- metric:dual_digest_separate_one_stack -->3<!-- /metric:dual_digest_separate_one_stack --> | <!-- metric:dual_digest_separate_one_executed -->5<!-- /metric:dual_digest_separate_one_executed --> | 19 | 1 |
| 4 | Shared | <!-- metric:dual_digest_shared_four_script -->241<!-- /metric:dual_digest_shared_four_script --> | <!-- metric:dual_digest_shared_four_witness -->638<!-- /metric:dual_digest_shared_four_witness --> | 4 | 0 (none) | <!-- metric:dual_digest_shared_four_stack -->6<!-- /metric:dual_digest_shared_four_stack --> | <!-- metric:dual_digest_shared_four_executed -->24<!-- /metric:dual_digest_shared_four_executed --> | 17 | 4 |
| 4 | Separate native | <!-- metric:dual_digest_separate_four_script -->237<!-- /metric:dual_digest_separate_four_script --> | <!-- metric:dual_digest_separate_four_witness -->638<!-- /metric:dual_digest_separate_four_witness --> | 4 | 0 (none) | <!-- metric:dual_digest_separate_four_stack -->6<!-- /metric:dual_digest_separate_four_stack --> | <!-- metric:dual_digest_separate_four_executed -->20<!-- /metric:dual_digest_separate_four_executed --> | 30 | 4 |

The single opening is 520 bytes. The four-opening witness, bottom to top,
contains lengths 0, 55, 56 and 520. Byte `i` is `(17*i+5) mod 251`.
Both schedules check the same two digest constants per opening and end with
true. Whole-artifact compilation uses policy `ALL`. Witness size includes
data count and length prefixes, excluding script, control block, annex and
transaction. All data items coexist at entry. Compression block counts
are derived from the algorithms and padding, with no timing measurement.

## Security

Each digest comparison is mandatory. The caller must provide the intended
public digest pair. Both digest functions share the same SHA-256 intermediate,
so collision resistance is not additive. No one-time key or security bound
is established.

## Script compatibility and standardness

These opcodes exist in bare script, P2SH, P2WSH and tapscript. Bare, P2SH and
P2WSH complete execution is unclassified. The measured execution is local
tapscript with the combined and element limits enforced, native MINIMALIF
enabled, numeric minimality and experimental OP_CAT disabled and a synthetic
transaction. The local policy profile rejects data items above 80 bytes.
Evidence is `locally-reproduced` and execution is `unclassified`.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

One arbitrary raw byte vector per opening, up to 520 bytes under the tested
local profile. Single and four-opening leaves have one and four data items
at entry, respectively. All cases need zero hint items and zero hint bytes.

## Stack contract

`caller | preimage -> caller`. The fragment does not touch altstack.
The peak is three items plus both preserved caller stacks. A batch of
`n` preloaded preimages peaks at `n + 2` plus caller state. Require an
exact input suffix and add a terminal predicate for a complete leaf.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/dual-digest-preimage.md)
for provenance, the derivation, negative results and deterministic commands.
The catalog record is `commitment/dual-digest-preimage`.
