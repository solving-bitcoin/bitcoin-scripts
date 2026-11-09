# Exact equality of raw multisets

`support::raw_multiset::verify_opaque_multiset_with_hints(n)` checks equality
of two width-`n) lists as multisets of raw stack items. Equal values must have
equal multiplicity. Both lists and all hints are hostile. No payload is
parsed as a number or hashed.

## Parameters

Width `n` is fixed at generation time in `1..=332`, with no default.
Payloads may have any allowed byte encoding, including empty and 520-byte
items. Only deletion hints are interpreted as ScriptNums.

## Script metrics

| Width | Schedule | Leaf bytes | Data witness bytes, including hints | Ordinary items | Hint items | Serialized hint bytes | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Greedy | <!-- metric:opaque_greedy4_script -->74<!-- /metric:opaque_greedy4_script --> | <!-- metric:opaque_greedy4_witness -->25<!-- /metric:opaque_greedy4_witness --> | 8 | 0 | <!-- metric:opaque_greedy4_hintbytes -->0<!-- /metric:opaque_greedy4_hintbytes --> | <!-- metric:opaque_greedy4_stack -->10<!-- /metric:opaque_greedy4_stack --> | <!-- metric:opaque_greedy4_executed -->38<!-- /metric:opaque_greedy4_executed --> |
| 4 | Hinted | <!-- metric:opaque_hinted4_script -->44<!-- /metric:opaque_hinted4_script --> | <!-- metric:opaque_hinted4_witness -->29<!-- /metric:opaque_hinted4_witness --> | 8 | 3 | <!-- metric:opaque_hinted4_hintbytes -->4<!-- /metric:opaque_hinted4_hintbytes --> | <!-- metric:opaque_hinted4_stack -->14<!-- /metric:opaque_hinted4_stack --> | <!-- metric:opaque_hinted4_executed -->31<!-- /metric:opaque_hinted4_executed --> |
| 16 | Greedy | <!-- metric:opaque_greedy16_script -->1477<!-- /metric:opaque_greedy16_script --> | <!-- metric:opaque_greedy16_witness -->97<!-- /metric:opaque_greedy16_witness --> | 32 | 0 | <!-- metric:opaque_greedy16_hintbytes -->0<!-- /metric:opaque_greedy16_hintbytes --> | <!-- metric:opaque_greedy16_stack -->34<!-- /metric:opaque_greedy16_stack --> | <!-- metric:opaque_greedy16_executed -->599<!-- /metric:opaque_greedy16_executed --> |
| 16 | Hinted | <!-- metric:opaque_hinted16_script -->219<!-- /metric:opaque_hinted16_script --> | <!-- metric:opaque_hinted16_witness -->124<!-- /metric:opaque_hinted16_witness --> | 32 | 15 | <!-- metric:opaque_hinted16_hintbytes -->27<!-- /metric:opaque_hinted16_hintbytes --> | <!-- metric:opaque_hinted16_stack -->50<!-- /metric:opaque_hinted16_stack --> | <!-- metric:opaque_hinted16_executed -->151<!-- /metric:opaque_hinted16_executed --> |
| Two of 16 | Greedy | <!-- metric:opaque_greedy16_twice_script -->2953<!-- /metric:opaque_greedy16_twice_script --> | <!-- metric:opaque_greedy16_twice_witness -->193<!-- /metric:opaque_greedy16_twice_witness --> | 64 | 0 | <!-- metric:opaque_greedy16_twice_hintbytes -->0<!-- /metric:opaque_greedy16_twice_hintbytes --> | <!-- metric:opaque_greedy16_twice_stack -->66<!-- /metric:opaque_greedy16_twice_stack --> | <!-- metric:opaque_greedy16_twice_executed -->1190<!-- /metric:opaque_greedy16_twice_executed --> |
| Two of 16 | Hinted | <!-- metric:opaque_hinted16_twice_script -->437<!-- /metric:opaque_hinted16_twice_script --> | <!-- metric:opaque_hinted16_twice_witness -->247<!-- /metric:opaque_hinted16_twice_witness --> | 64 | 30 | <!-- metric:opaque_hinted16_twice_hintbytes -->54<!-- /metric:opaque_hinted16_twice_hintbytes --> | <!-- metric:opaque_hinted16_twice_stack -->97<!-- /metric:opaque_hinted16_twice_stack --> | <!-- metric:opaque_hinted16_twice_executed -->302<!-- /metric:opaque_hinted16_twice_executed --> |

All checked leaves include complete multiplicity verification and terminal
true, with whole-script optimizer `ALL`. Witness bytes include every entry
item and its serialization prefixes and exclude script, control block,
annex and transaction. Hint bytes include each hint length prefix, excluding
the shared witness item-count prefix. Both schedules consume the same
ordinary payloads. All data and hints coexist at entry, including both
invocations in the two-of-16 rows. Non-push opcode counts include encountered
branch delimiters.

## Security

Each hint must be a canonical at-most-four-byte ScriptNum in the current
pool range. Script moves and removes the chosen item, then verifies exact
byte equality against the corresponding right item. Duplicate byte values
can have multiple valid hints. No left item can be used twice. The caller
must bind the exact input suffix and any required application identities.

## Script compatibility and standardness

The used opcodes exist in bare script, P2SH, P2WSH and tapscript. Bare, P2SH
and P2WSH complete validity is unclassified. The local tapscript
`Consensus` profile enforces stack and element limits and MINIMALIF, with
numeric minimality and experimental OP_CAT disabled. Execution is
`unclassified` and evidence is `locally-reproduced`.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Bottom to top, supply
`left[0] ... left[n-1] right[0] right[1] hint[1] ... right[n-1] hint[n-1]`.
For each right item in descending order, find an equal item in the remaining
left pool, record its top-relative depth and remove it. No hint is needed
for `right[0]`. This yields `2n` ordinary items and `n-1` hints at entry.
The combined peak is at most `3n+2` for `n>=2` and two for `n=1`, plus
both caller stacks and all future inputs. Altstack is unused.

## Stack contract

`caller | two lists and interleaved hints -> caller`. Both lists and all
hints are consumed. Add a terminal predicate for a standalone leaf.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/opaque-multiset.md)
for fixture generation, exact measured tradeoffs, negative results and
reproduction. The catalog record is `support/opaque-multiset`.
