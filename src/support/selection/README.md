# Stable selection of opaque stack items

`support::selection::compact_selected_items(n)` consumes payload/selector pairs
and returns a stable retained subsequence plus its canonical numeric count.
Payloads are uninterpreted bytes. Every selector is hostile and must be exactly
empty (discard) or `01` (retain), enforced by tapscript MINIMALIF. The caller
must authenticate selector meaning where required and bind the resulting count
and payloads. This fragment provides no cryptographic authentication.

## Parameters

`pair_count`: generation-time integer in `0..=499`, no default. Both caller
stacks are preserved, but their combined live state shares the 1,000-item limit.
There is no payload size parameter: entry elements may contain up to 520 bytes
under the local consensus profile; local policy permits at most 80 bytes.

## Script metrics

Fragment bytes include count initialization, selection under native MINIMALIF,
discard cleanup, altstack staging and stable output restoration. They exclude
input pushes and terminal predicates. The complete leaf below checks count 32,
then every retained raw `42` payload, and returns one true item. Witness bytes
include the item count and length prefixes for all 64 input data items; they
exclude script, control block, annex and transaction serialization. Zero hints
are used. All input items, including discarded payloads, coexist at entry.

| Configuration | Script bytes | Serialized data witness | Hint items | Combined peak |
| --- | ---: | ---: | ---: | ---: |
| 32 pairs, all retained, fragment | <!-- metric:stable_selection32 -->496<!-- /metric:stable_selection32 --> | <!-- metric:stable_selection32_witness -->129<!-- /metric:stable_selection32_witness --> | 0 (none) | <!-- metric:stable_selection32_stack -->65<!-- /metric:stable_selection32_stack --> |
| Same inputs, complete output-checking leaf | <!-- metric:stable_selection32_leaf -->596<!-- /metric:stable_selection32_leaf --> | 129 | 0 (none) | 65 |

The fragment has <!-- metric:stable_selection32_static -->448<!-- /metric:stable_selection32_static -->
static non-push opcodes; the leaf has 481. These counts are not dynamic executed
opcode counts. The interpreter's instruction-position counter includes pushes
and skipped instructions, so executed opcodes are unavailable. No signatures
execute; measured signature weight charged is zero, without establishing a
complete transaction budget.

| All retained | Fragment / complete leaf bytes | Data items | Witness bytes | Peak |
| --- | ---: | ---: | ---: | ---: |
| 128 pairs, one-byte payloads | 2,032 / 2,421 | 256 | 515 | 257 |
| 499 pairs, one-byte payloads | 8,339 / 9,841 | 998 | 1,999 | 999 |
| 499 pairs, 520-byte payloads | 8,339 / 270,319 | 998 | 261,978 | 999 |

All three fragments use optimizer `ALL`. The 270,319-byte leaf is explicitly
**unoptimized** (`NONE`): its raw serialization exceeds the 32 KiB policy cutoff.
The 499-pair leaf binding 80-byte payloads is also unoptimized: 50,260 bytes.
Independent compilation of a fragment cannot determine the whole leaf's policy.
The [report](../../../research/stable-stack-compaction/metrics.json) records
raw sizes, options, final hashes, witness hashes and boundaries for every row.

Catalog fragment `witness_bytes_max` covers every legal selector and 520-byte
payload at that pair count, even for a representative all-drop fixture. The
catalog's all-retained literal-checking leaves have a fixed successful witness,
so their maximum equals that witness rather than the fragment's general maximum.

## Security

This is deterministic routing, with no independent cryptographic security
claim or one-time key. Native MINIMALIF rejects nonbinary values, negative zero,
raw zero and overlong encodings rather than normalizing them. Opaque payloads
are never parsed as numbers or certified as valid limbs, points or commitments.
Discarded payloads may vary without altering output; selection does not bind
them to an authenticated input transcript. Bind selected content, retained
count and selector meaning in the calling protocol.

## Script compatibility and standardness

- **Bare/legacy:** the opcodes exist, but native truthy IF does not establish
  this exact binary contract. The 32-pair fragment also exceeds the legacy
  201-opcode limit. No legacy result is claimed for smaller configurations.
- **P2SH:** the 32-pair complete leaf exceeds the 520-byte redeem-script bound
  and the legacy opcode limit. Smaller variants need their own validation.
- **P2WSH:** the 32-pair fixture exceeds the legacy 201-opcode limit. Native
  tapscript MINIMALIF evidence does not transfer to a Segwit-v0 fragment.
- **Tapscript:** the explicit local `Consensus` profile enforces native
  MINIMALIF, 520-byte entry elements and the 1,000-item combined limit. Its
  synthetic transaction and data-only witness do not validate a Taproot spend.
  Local `Policy` rejects initial payloads above 80 bytes, even discarded ones.
  Large literal leaves additionally need full transaction/weight accounting.

Evidence is `locally-reproduced`; deployment is `unclassified` for every
catalog configuration. No Bitcoin Core differential or relay acceptance is
claimed. See [script types](../../../docs/script-types.md),
[standardness](../../../docs/standardness.md) and the
[local profiles](../README.md#explicit-fragment-profiles).

## Witness and hints

Bottom to top: `data[0] flag[0] ... data[n-1] flag[n-1]`. Payloads may be empty,
negative-zero bytes, five-byte nonnumbers or any other allowed raw item.
Flags are exactly empty or `01`. There are **0 hint items per invocation**, and
**2n ordinary witness data items**, all present at entry. For sequential batches
preloaded together, sum all `2n` data counts; hints remain zero and future
inputs still contribute live state. The return count is produced by Script,
not supplied as a witness hint. Discarding an item does not erase its entry
element-size or policy obligation.

## Stack contract

Main: `caller | pairs -> caller | retained[0] ... retained[k-1] | k`.
Altstack: arbitrary caller state is preserved exactly. Backward consumption
parks selected payloads above caller altstack state in reverse order;
count-bounded restoration produces original input order on main. The output
count is minimally encoded. Empty input returns zero without consuming state.

Combined peak before caller state is 1 at `n=0`; 3 for a discarded `n=1`
or 4 when retained; and `2n+1` at `n>=2`. Budget 4 for an unknown one-pair
selector. Add **both** preserved caller stacks. At `n=499`, one caller item
fits exactly at 1,000; a second rejects with typed `StackSize`. A 500-pair
research baseline enters with 1,000 items and fails when it initializes count.
Constructor values above 499 are rejected. All surviving outputs and count
need consumption or checks plus a terminal predicate; this fragment is not a
clean-stack locking script.

## Operational notes

The matched native forward baseline costs 970 fragment / 1,070 leaf bytes at
32 pairs and peaks at 66, versus 496/596/65 here. At 499 pairs it costs
18,800/20,302/1,000. Explicit numeric guards are redundant under tapscript
MINIMALIF: backward 32-pair selection costs 816 bytes and peaks at 68; those
guards reduce the measured no-caller frontier to 498 pairs.

The shared contract suite covers all masks through eight pairs, long asymmetric
vectors, opaque payloads, every malformed selector position, numeric aliases
under the existing word selector's distinct contract, short inputs, observable
caller state, exact frontiers, local policy, output/count substitutions and
compiled validation bypasses. Bypass mutants preserve valid controls and are
caught by the same intended typed-error assertion with unchanged cleanup.
The existing word selector keeps its numeric truthiness API and does not
certify limbs; only its documentation is clarified.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test selection_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics stable_selection_metrics_are_current
python3 tools/kb.py validate
```

See the [reproduction guide](../../../research/stable-stack-compaction/README.md)
for immutable source and dependency pins.

## Knowledge-base integration

Catalog `support/stable-selection`; [knowledge page](../../../knowledge/primitives/stable-selection.md),
[comparison](../../../knowledge/comparisons/stack-selection.md),
[composition](../../../knowledge/techniques/composition.md#stable-selection-with-native-binary-flags),
[NR-078](../../../knowledge/negative-results/stable-selection.md) and
[OP-036](../../../knowledge/open-problems.md#op-036--stable-selection-protocol-composition).
