# Decode a single contiguous run from binary flags

Can one signed counter carry both the run length and its closed state?
The hypothesis is that this representation removes a live stack item and
reduces script bytes relative to a separate phase flag. Both constructions
receive the same hostile binary flags and return the same canonical
zero-based start and positive length. The hard constraints are a fixed
width, native tapscript MINIMALIF, at most 1,000 combined items, zero hints
and the central compilation policy. Evidence is `locally-reproduced`;
execution is `unclassified`.

`arithmetic::interval_mask::decode_single_run(n)` consumes the exact suffix
`flag[n-1] ... flag[0]`, with the earliest flag on top. It accepts the
language `0* 1+ 0*`. Each successful flag is exactly the empty vector or
`01` under [BIP 342 MINIMALIF](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki).
The first flag initializes `(start, length)` to `(1, 0)` or `(0, 1)`
before allocating the state for subsequent flags. This same initialization
is used in both schedules.

- A zero signed length means the run has yet to start. On another false
  flag, increment the start.
- A positive signed length means the run is open. A true flag extends the
  run. A false flag closes it by storing the negative of its length.
- A negative signed length means the run has closed. Later false flags
  keep that value. A subsequent true flag rejects.

At the end, take the absolute value and require it to be nonzero. The
separate-state baseline represents the same transitions with a third
stack item, a canonical closed flag. The source search covered the catalog,
comparisons, negative results, source and matching pull requests. The
closest existing [u4 transition fold](u4-transition-count.md) counts
adjacent changes and discards their locations. The
[opaque-payload selector](stable-selection.md) filters based on a general
binary mask and accepts noncontiguous selections.

## Matched complete leaves

| 32 flags, indices 5 through 12 true | Script bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Signed length | 602 | 41 | 32 | 0 | 33 | 352 |
| Separate closed flag | 698 | 41 | 32 | 0 | 35 | 354 |

Both leaves verify the canonical encodings of start 5 and length 8 and leave
one true item. The whole leaf uses optimizer `ALL`. Script bytes include
validation, routing, state transitions and terminal checks. Serialized
witness bytes include count and item-length prefixes for all 32 ordinary
items, excluding script, control block, annex and transaction. All flags
coexist at entry. Both fixtures have zero caller items and zero hints.
The dynamic trace counts active non-push opcodes and encountered branch
delimiters. Signature weight charged is zero.

The local tapscript `Consensus` profile uses a synthetic empty transaction.
Stack and element limits and MINIMALIF are enabled. Numeric minimality and
experimental OP_CAT are disabled. The compiler and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).

## Resource and caller boundary

The signed-length generator permits `1..=998` flags and has a conservative
combined bound of `n + 2` plus both caller stacks. The first flag is consumed
before two state items are created, so the remaining flags, two state items
and the temporary roll depth fit this bound. After consuming a flag, two
temporary comparison items also fit. The separate-flag baseline needs one
more item. The optimized 32-flag fixture peaks below the signed-length bound.

The frontier test uses one leading false flag, 166 true flags and trailing
false flags. The signed-length version reaches 1,000 at 998 flags, while the
separate-flag version reaches 1,000 at 997 flags and rejects 998. With one
caller item on each stack, the signed version reaches 1,000 at 996 flags and
rejects an additional caller item. The fragment preserves both caller stacks
given the exact input suffix. Every preloaded invocation contributes all of
its flags as live items. Check or consume both outputs before the terminal
predicate. Bind the flags or interval if a protocol depends on who chooses
the range. Funded Core and relay checks are outside this experiment.

Both schedules match a host interval oracle on all 510 binary masks of
widths one through eight. The tests reject all-zero and split masks even
without an output predicate, malformed flags at every position, 521-byte
items, short or surplus witnesses, and wrong expected start or length.
See the [negative result](../negative-results/single-run-mask.md) for an
executable case where transition count alone accepts a split mask.

```sh
cargo test --locked --lib arithmetic::interval_mask::tests
cargo test --locked --test primitive_metrics single_run_mask_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation README](../../src/arithmetic/interval_mask/README.md)
and catalog record `arithmetic/single-run-mask`.
