# Decimal Damm checksum with a resident transition table

`arithmetic::u4::damm::u4_decimal_digits_to_damm(n)` consumes numeric decimal
Script digits left to right and returns the canonical Damm state, initially
zero. It installs one fixed 100-entry transition table, validates every hostile
digit and removes the table before returning. Both caller stacks are preserved.
This is an error-detecting checksum; the caller must authenticate message meaning
where required and bind length, result and a terminal predicate.

## Parameters

`digit_count`: generation-time integer in `0..=896`, no default. Empty input
returns zero; positive input uses the resident table. This numeric empty-fold
extension is distinct from the pinned reference's string API, which rejects
empty text and requires at least two characters in its validation wrapper.

## Script metrics

Fragment bytes include the entire table setup/cleanup, numeric digit guards,
forward routing, state initialization and return. They exclude input pushes and
terminal predicates. The complete measured leaf checks the exact final state
and returns TRUE. Witness bytes include every ordinary data item and count/length
prefix; exclude leaf, control block, annex and transaction. Zero hints are used,
and every input coexists at entry.

| Configuration | Script bytes | Serialized data witness | Hint items | Combined peak |
| --- | ---: | ---: | ---: | ---: |
| 32 digits `(7*i+3)%10`, fragment | <!-- metric:u4_damm32 -->766<!-- /metric:u4_damm32 --> | <!-- metric:u4_damm32_witness -->61<!-- /metric:u4_damm32_witness --> | 0 (none) | <!-- metric:u4_damm32_stack -->136<!-- /metric:u4_damm32_stack --> |
| Same digits, state-9 checked leaf | <!-- metric:u4_damm32_leaf -->769<!-- /metric:u4_damm32_leaf --> | 61 | 0 (none) | 136 |

The fragment has <!-- metric:u4_damm32_static -->532<!-- /metric:u4_damm32_static -->
static non-push opcodes; the leaf has 533. Dynamic executed-opcode counts are
unavailable: the interpreter's position counter includes pushes and inactive
instructions. No signatures execute; zero charged signature weight is recorded
separately and is not a complete transaction-budget measurement.

| Mixed numeric fixture | Fragment / checked leaf | Canonical witness | Four-byte alias witness | Peak |
| --- | ---: | ---: | ---: | ---: |
| 1 digit | 172 / 175 | 3 | 6 | 105 |
| 128 digits | 2,686 / 2,689 | 244 | 641 | 232 |
| 896 digits | 18,046 / 18,049 | 1,705 | 4,483 | 1,000 |

Every public fragment and listed leaf uses policy `ALL`. The independent
[report](../../../../research/damm-finite-state/metrics.json) records raw size,
whole-artifact options, final script/witness/output hashes and source bindings.
Large comparison scripts cross the 32 KiB raw cutoff: the 128-digit table-free
baseline is **unoptimized** `NONE` at 113,731 bytes; do not transfer the public
fragment's optimization status to a comparison or composed leaf.

A canonical numeric digit occupies at most two serialized data bytes; a permitted
four-byte numeric alias occupies five. Maximum witness size is therefore
`5*n + CompactSize(n)`, including aliases, and is attained by the same numeric
message with every digit encoded in four bytes. A checksum-only leaf does not
fix one unique witness, so its maximum uses the same boundary. For 32 digits the
representative witness is 61 bytes, canonical maximum 65, full allowed maximum
161. Local policy rejects the four-byte aliases with `MinimalData`.

Independent preloaded folds are priced in the report's `compositions` collection:
each has 32 ordinary data items and zero hints, so two folds have 64 data items /
0 hints and 28 have 896 / 0, all at entry. Every returned state and future input
is included in combined peak. The report attributes any whole-script optimizer
delta against independently compiled fragments plus park/restore operations.

At 32 digits the independently policy-compiled lifecycle is 100 bytes of table
setup, one byte of initial state, 613 bytes of validated queries/routing, and
52 bytes of table cleanup/state restoration. The whole optimizer delta is zero,
so these sum to the final 766-byte fragment. At 128/896 digits, query/routing
components are 2,533/17,893 bytes; setup/state/cleanup remain 100/1/52 and deltas
remain zero. Query depth encodings vary with n, so this is not a constant
per-digit charge or a shared-table API.

## Security

The result has ten possible values and supplies no cryptographic authentication
or one-time-key property. The fixed table's row/column permutations, zero diagonal
and all adjacent unequal-digit state relations are locally checked. These imply
single numeric digit substitutions and adjacent unequal numeric digit swaps of
valid fixed-length codewords change the final state; the suffix preserves the
state difference because each column is a permutation. This is an inference
from the exhaustively checked finite table, also tested on all three-digit
codewords with every single substitution and adjacent swap.

An attacker can compute a new trailing check digit for any changed message.
Distinct same-length prefixes `00` and `13` both have state zero, and `000` /
`130` are both valid codewords. Leading zeros do not bind length. Numeric aliases
of the same digit deliberately produce the same state; no byte-unique encoding
or byte-error guarantee is supplied. The caller binds message semantics,
length/order and authorization separately.

## Script compatibility and standardness

- **Bare/legacy:** uses ordinary enabled stack/numeric opcodes, but the 32-digit
  fragment has 532 static non-push opcodes and exceeds the legacy 201 limit.
  Smaller configurations require separate context validation.
- **P2SH:** the 769-byte representative leaf exceeds the 520-byte redeem-script
  bound and the legacy opcode limit. No smaller configuration is promoted.
- **P2WSH:** the representative fragment exceeds the 201-opcode limit; large
  fragments also exceed the legacy 10,000-byte script bound.
- **Tapscript:** explicit local `Consensus` execution enforces 520-byte elements
  and the 1,000-item combined limit, permits nonminimal numeric aliases and has
  experimental OP_CAT disabled. Internal branch predicates are canonical.
  Local `Policy` additionally rejects aliases and initial elements above 80
  bytes, but it is only a partial fragment-policy check.

Every catalog configuration is `locally-reproduced` / `unclassified`. No funded
transaction, Taproot commitment, Bitcoin Core differential or relay acceptance
is established. See [script types](../../../../docs/script-types.md),
[standardness](../../../../docs/standardness.md) and
[local profiles](../../../support/README.md#explicit-fragment-profiles).

## Witness and hints

Bottom to top: `digit[0] ... digit[n-1]`. Every item is an at-most-four-byte
ScriptNum numerically in `0..=9`. These are numeric digits, not ASCII characters.
Nonminimal encodings are accepted when the execution profile permits them.
The output is canonical. There are **n ordinary data items and 0 hint items per
invocation**, with zero serialized hint bytes; all inputs are present at entry.
For r preloaded independent n-digit messages, data items total `r*n`, hints
`r*0 = 0`; future messages and previously produced states share the same limit.
A supplied trailing check digit is another ordinary digit counted in n, not a
free hint. To validate a codeword, consume its entire digit sequence, check state
zero and leave a terminal predicate. Dropping a result alone does not bind it.

## Stack contract

Main: `caller | digit0 ... digit[n-1] -> caller | canonical state`.
Altstack: caller state is preserved. The fixed table lives above the inputs;
static-depth ROLL retrieves the next leftmost digit. Each checked transition
forms `10*state+digit` and copies its table entry. The final state is parked
while all 100 table entries are dropped, then restored.

Combined peak excluding caller state is 1 when empty, otherwise `n+104`.
Add both caller stacks, including future input groups. At n=896 no extra item
fits; at n=32 caller capacity is 864 items. The strict suite observes every
preserved caller and returned item at exactly 1,000 and rejects one additional
item with typed `StackSize`. The 897-digit unbounded research version fails at
1,001; the public constructor rejects it. This fragment returns data and is not
by itself a clean-stack locking predicate.

## Operational notes

At 32 digits the matched first-row/ten-entry-row-table baseline costs 5,652
bytes and peaks at 42, versus 766/136 here. Table-free dispatch costs 27,809/35.
At two digits resident lookup costs 191/106 versus row-table 206/12. At one
it loses: resident 172/105, row-table 27/11, dispatch 81/4. Warmup dispatch before
resident installation saves one live item but costs 63 extra bytes at n=32;
these alternatives remain scoped comparisons, not extra public APIs.

The shared contract suite covers four Damm schedules and the existing canonical
modulo-16 and numeric exact sums under their own contracts. It covers short and
asymmetric inputs, aliases, malformed values at every small and representative
position, exact caller-state frontiers, local policy, arity/result/order bindings,
compiled range/canonicality/terminal bypasses, and all preloaded results.
Valid controls pass the same harness; the same intended typed-error assertion
catches each validation bypass with correct unchanged cleanup. Sibling APIs and
catalog classifications are preserved.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test damm_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics u4_damm_metrics_are_current
python3 research/damm-finite-state/verify_metrics.py
python3 tools/kb.py validate
```

Source matrix and fold semantics are pinned to
[CheckDigits.Net 734afa2d](https://github.com/KnowledgeForwardSolutions/CheckDigits.Net/tree/734afa2d3596862ef4c3bb3ec404b512b96b8965),
with exact source bytes and [MIT license](../../../../research/damm-finite-state/reference/LICENSE.txt)
preserved. Original C# execution is not claimed. The
[reproduction guide](../../../../research/damm-finite-state/README.md) separates
original prototype and integrated source pins.

## Knowledge-base integration

Catalog `arithmetic/u4-damm`; [knowledge page](../../../../knowledge/primitives/u4-damm.md),
[lookup comparison](../../../../knowledge/comparisons/lookup-strategies.md#damm-finite-state-folds),
[negative result NR-079](../../../../knowledge/negative-results/damm-finite-state.md),
[composition](../../../../knowledge/techniques/composition.md#independent-decimal-checksum-folds)
and [OP-037](../../../../knowledge/open-problems.md#op-037--authenticated-decimal-transducer-composition).
