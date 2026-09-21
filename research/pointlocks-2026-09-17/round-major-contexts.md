# Six anchored contexts below 100,000 vB by changing witness order

Question: can the anchored candidate retain six distinct short-signature
contexts per selected label while including all output creation, consumption
and authorization below 100,000 vB? **The new serialization estimate is
98,334 vB.** It uses 95 five-of-54 pools. Core validates the actual full-pool
script at its 201-opcode boundary. The later
[complete publication](round-major-publication.md) is signed, Core-accepted
and mined at **98,323 vB**. General extraction and protocol setup remain open.

[Generator](../../examples/pointlock_anchored_round_major_probe.rs),
[size report](anchored-round-major-size.json),
[native harness](round_major_core_check.py),
[small Core report](round-major-core-check.json),
[full-pool Core report](round-major-full-pool-core-check.json),
[sizing provenance](round-major-provenance.json).

## Why grouping checks by round saves resources

The previous [phased layout](shared-anchor-context.md) completes every short
check for one key before moving to the next. The new witness instead places
all short signatures above a retained stack of the selected keys. After the
unchanged destructive hash-table selection, verification proceeds as follows:

1. Verify all selected anchors, copying their matching keys with `OP_PICK`.
2. Verify round zero for every selected key in the anchor's scriptCode.
3. For each later round, execute one `OP_CODESEPARATOR`, then check one
   60-byte signature per selected key.
4. In the final round consume the original keys with `OP_ROLL`, rather than
   leaving copies to clean up afterwards.

There are only `d-1` separators per pool, instead of `t*(d-1)`. Each selected
key still receives d distinct scriptCode suffixes. All anchors and all first
round checks share a suffix; their actual digests are equal only when the
remaining sighash context, including the raw flag, matches. The anchors
still have their committed ALL flag. Other consensus-permitted flags remain
available for the short signatures.

For t selected keys and d rounds, number keys by verification order, which
is the reverse of destructive selection order. At anchor j, the copied key
has depth `d*t+j+1`, including the newly popped anchor. During any earlier
short round r, its depth is `(d-r)*t`: consuming prior signatures and moving
to the next key cancel. In the last round, `t-j OP_ROLL` consumes the original
key. Each signature is still checked for exact length 60 immediately before
its ECDSA check. These are witness-order and context-sharing changes;
routine local opcode rewriting is left to `compile_with_policy()`.

The public setup rule rejecting table hashes beginning with `0x30` is retained.
It excludes the nonempty DER-signature shape needed by the typed selector's
zero/outside-index cases. The layout does not count different reveal orders
as additional message capacity.

## Complete serialization boundary

The bounded scan considers n=3..120, t=1..8 and d=5..8, using a conservative
opcode prefilter and actual policy-compiled scripts for retained profiles.
It records 1,960 feasible rows. It repeats one homogeneous profile per row;
this is not a global optimum or a representation lower bound.

| Contexts per label | Pool | Pools | Script B | Witness B per pool | Charged ops | Create vB | Spend vB | Combined vB |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 5 | 5-of-68 | 88 | 1,763 | 3,750 | 187 | 3,895 | 86,219 | 90,114 |
| 6 | 5-of-54 | 95 | 1,503 | 3,795 | 201 | 4,196 | 94,138 | **98,334** |
| 7 | 4-of-59 | 109 | 1,579 | 3,672 | 187 | 4,798 | 104,642 | 109,440 |
| 8 | 4-of-53 | 113 | 1,483 | 3,820 | 201 | 4,970 | 112,659 | 117,629 |

Creation includes an initial P2TR input, the first P2TR helper output and
every P2WSH output. Spending consumes the helper and every publication output
and creates the final P2TR output. Every pool reserves a 72-byte authorization
signature. CompactSize fields, witness item lengths, marker/flag, input/output
framing and per-transaction vbyte rounding are included. The six-context
spending estimate is 376,549 WU, below the standard weight ceiling. Seven
and eight contexts exceed that ceiling for the unsplit spending transaction;
their rows do not include any additional splitting transaction.

The six-context profile has 5,130 candidate labels, 475 scalar openings and
2,850 short checks. `binomial(54,5)=3,162,510`; its 95-pool product has
approximately 2,051.30 bits of capacity, enough for every 2,048-bit message.
This capacity calculation does not implement a total garbled decoder for
surplus codewords. The existing four-of-50 decoder and its benchmark cannot
be reused as evidence for this changed profile.

The five/six/seven/eight-context rows require respectively 5/5/4/4 hint items
per input, 41/46/41/45 entry data items and 42/47/42/46 complete witness
items. Hints coexist with all other entry data in their input. Totals across
the respective publications are 440/475/436/452 hints and
3,608/4,370/4,469/5,085 entry items. The reported per-input combined-stack
upper bounds are 115/106/106/104, all below 1,000; different inputs have
independent stacks. All reported scripts are optimized, below 32 KiB.

Size evidence: **locally-reproduced**; deployment: **unclassified**. The
full-size table is repeated placeholder data, and signatures/recovered keys
in the sizing witnesses are placeholders. These are not native full-message
transactions or setup benchmarks.

## Native and structural verification

A focused Rust test checks the compiled context layout for t=1..5 and d=1..8:
there are `d-1` separators, `1+t+t*d` signature checks including authorization,
and d distinct short suffixes for each label. A separate value/height trace
checks native BIP143 digests, every ECDSA equation and clean-stack behavior.
Bitcoin Core 30.3 is the independent consensus and policy oracle.

| Fixture | Positive cases | Negative cases | Script B | Witness B | Charged ops | Hints | Entry items | Complete witness items | Combined peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2-of-4, six rounds | 12 | 10 | 233 | 1,182 | 74 | 2 | 19 | 20 | 23 |
| 5-of-54, six rounds | 6 | 9 | 1,503 | 3,783 | 201 | 5 | 46 | 47 | 100 |

Every positive is accepted by default mempool policy and mined; every
negative fails both policy and block validation. The small fixture covers
all ordered selections. The full pool covers lowest, highest and spread
indices in both directions. Negatives cover invalid indices, zero/negative
zero with matching hash equations, oversized ScriptNums, extra data, swapped
recovered keys, wrong short-item size and cross-round signature replay. The
small fixture additionally exercises the crafted outside-table hash case.

The independent extractor recovers all intended fixture scalars using their
publicly known G/2 nonces. Across positive executions the small fixture has
24 hint occurrences and 228 entry-item occurrences; the full pool has 30
hints and 276 entry items. They are independent executions, not one combined
stack. The peak measurements come from the independent trace, not a Core
instrumentation counter. Native authorization signatures are 60 bytes in
these public fixtures, explaining the 12-byte difference from the 72-byte
reservation in the full-size estimate. Test-only funding is not a complete
message-publication cost measurement.

Native evidence: **differentially-validated**; positive fixture deployment:
**policy-validated**. Core commit is
`49faec4f87f5cd19c88db01a82e5c68b087c8227`; compiler commit is
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. The tapscript/stack-unlimited
helper is not used. Reports retain exact transactions and source hashes.

```sh
cargo test --locked --example pointlock_anchored_round_major_probe
cargo run --release --locked --example pointlock_anchored_round_major_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/round_major_core_check.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/round_major_core_check.py --full-pool
```

## What this changes for the goal

Six anchored contexts now fit the complete serialized byte budget, removing
the previous layout's 103,345-vB obstacle. This does **not** establish a
sufficient repetition count. The existing alternative-nonce cost model
already gives a six-context screened strategy around `2^74.59` nonce-point
trials and `2^71.63` scalar checks when 256 flags are available; these are
heuristic upper-work estimates in different units, not a lower bound or a
proved attack on this new layout. Shared contexts also require analysis of
cross-label correlations and adaptive selection.

The [95-pool publication follow-up](round-major-publication.md) now supplies
fully signed native transactions and 475 independently recovered scalars,
plus a scoped point-lock setup benchmark. An all-consensus extraction
argument, publicly bound total label decoder and garbled verifier,
mandatory-input binding, and complete setup benchmark remain required.
The goal remains open; passing honest fixtures do not substitute for these.
