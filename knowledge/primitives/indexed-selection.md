# Sparse indexed selection of opaque stack items

Can a witness of strictly ordered positions select a fixed-size stable subset
of opaque payloads more cheaply than one binary flag per payload? The
hypothesis is that validating only retained positions reduces data items,
script bytes and executed operations at low density. Compare the existing
native binary-flag compactor with the same payloads, count and selected byte
sequence. All witness items are hostile. The experiment requires canonical
selectors with numeric minimality disabled, byte-exact payload preservation,
520-byte elements, no new opcodes, and a combined stack peak at most 1,000.
Its evidence is `locally-reproduced` and execution is `unclassified`.

The public fragment `compact_indexed_items(n, k)` accepts generation-time
parameters `1 <= k <= n` and `n + k <= 996`. Put all `n` payloads on the stack
first, then the `k` indices in reverse consumption order. Depth zero means the
last original payload. Each depth must be a canonical four-byte-or-smaller
ScriptNum, strictly greater than the previous depth (initially −1), and less
than `n`. The result contains the selected payloads in input order and their
canonical count. The indices define the selection and are ordinary data, so
every invocation has zero hints.

## Why the roll stays inside the payload block

On round `j`, `j` previously selected shallower payloads have moved to the
altstack. The remaining depth of the target within the payload block is
`depth - j`. Above that block are `k - j - 1` unread selectors and the saved
current depth. The argument for `OP_ROLL` is therefore `depth + k - 2j`.
The strict ordering gives `j <= depth < n`. This places the roll below all
control items and within the remaining payloads. Rolls stage the selected
items from shallowest to deepest. After dropping the unselected items,
restoring from altstack returns the stable subsequence.

The schedule follows the stack semantics of [Bitcoin Core v30.3 OP_ROLL](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L753-L777).
Stable subsequence semantics follow the pinned
[C++ draft copy_if specification](https://github.com/Eelis/draft/blob/c7015b485cc3db8efaa9dfb9ff0809c5394a4ed1/source/algorithms.tex).
The scoped prior-art search covered the catalog, stack-selection comparison,
negative results, source tree and open PRs. The local binary-flag compactor is
the direct baseline. The search establishes a catalog gap.

## Measured complete leaves

| Retained of 32 | Encoding | Script bytes | Witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Indices | 114 | 72 | 36 | 0 | 40 | 87 |
| 4 | Flags | 511 | 101 | 64 | 0 | 65 | 309 |
| 16 | Indices | 402 | 96 | 48 | 0 | 52 | 297 |
| 16 | Flags | 547 | 113 | 64 | 0 | 65 | 369 |
| 32 | Indices | 792 | 128 | 64 | 0 | 68 | 575 |
| 32 | Flags | 596 | 129 | 64 | 0 | 65 | 449 |
| 32 | Identity | 97 | 65 | 32 | 0 | 33 | 32 |

Payload `i` is the single byte `0x20 + i`. The kept original depths are
`floor(j * 32 / k)` for `0 <= j < k`. The identity uses no selectors because
the output contains every input position. Every leaf verifies the same count
and each selected raw payload and ends with one true item. Each script metric
includes all checks, routing, discard cleanup and terminal checks. Every leaf
uses whole-artifact optimizer `ALL`. Witness bytes are the serialization of
all entry data, including discarded payloads and count/length prefixes, with
script, control block, annex and transaction excluded. Every row has zero
caller items and no input pushes. The opcode trace counts active non-push
operations and branch delimiters handled in inactive branches. Signature
weight charged is zero. These figures use the local tapscript `Consensus`
profile with a synthetic empty transaction, MINIMALIF and stack/element
limits enabled, numeric minimality and experimental OP_CAT disabled.

At 4 of 32, the indexed leaf saves 397 script bytes and 29 serialized witness
bytes while using 25 fewer peak items. At 16 of 32 it still saves 145 script
bytes and 17 witness bytes. The full-subset index and flag versions both lose
to identity on every measured resource except hint count, which ties. See
[NR-078](../negative-results/stable-selection.md#sparse-indices-at-full-density).

## Composition and reproduction

The fragment needs an exact input suffix. It preserves both caller stacks,
which add directly to the `n + k + 4` peak. At the first canonical check the
saved previous depth, two duplicates and zero account for four extra items.
Subsequent rounds have fewer live inputs. With no caller state, `(995, 1)`
and `(992, 4)` reach 1,000. With one live item on each caller stack,
`(993, 1)` reaches 1,000 and `(994, 1)` rejects at 1,001. Every future
invocation preloaded on either stack adds its full ordinary item count.

The caller must establish the input boundary and bind any required position
semantics. Identical payloads at different positions make output bytes alone
insufficient to identify a chosen position. Discarded items can vary without
affecting the result, and all items still count toward entry limits. A checked
leaf needs an output/count predicate and clean stack. Full Taproot and relay
validation for a real consumer are tracked in
[OP-036](../open-problems.md#op-036--stable-selection-protocol-composition).

```sh
cargo test --locked --test selection_contract indexed_selection
cargo test --locked --test primitive_metrics indexed_selection_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests check all 502 nonempty subsets across widths one through eight,
malformed controls, missing and extra entry items, wrong output bindings,
opaque 520-byte payloads and exact main-plus-alt-stack frontiers. The compiler
and interpreter are the `Cargo.lock` pins
[124b561ed75ac3ec4c6ad99207d8dcdd3bc67180](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [a09e87af444034698697f0a2267e755cf72f9aed](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
See the [implementation README](../../src/support/selection/README.md#sparse-index-input)
and the catalog record `support/indexed-selection`.
