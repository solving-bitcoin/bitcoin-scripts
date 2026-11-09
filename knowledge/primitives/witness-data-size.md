# Serialized witness-data byte cap

Can a Script check a byte cap on the serialization of a fixed suffix of
opaque data items while preserving both stacks? The hypothesis is that
a sufficiently tight public cap makes all individual long-prefix checks
redundant. Compare against an exact branch-based check with identical
stack contracts, inputs, cap, and terminal cleanup. For larger caps,
also price branch-free exact accounting against the same baseline.

## Construction

[BIP 144](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0144.mediawiki#serialization)
defines a witness vector as a count and length-prefixed items. The
[pinned Core CompactSize implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/serialize.h)
uses a one-byte prefix below 253 and three bytes for the lengths of
larger admissible data items. With `n` items, set
`base = CompactSizeWidth(n) + n`. The raw-length subtotal plus `base`
is a lower bound, and it is exact when every item is shorter than 253.
If a public cap is less than `base + 253`, any item with a long prefix
already exceeds the cap by the lower bound. The generator then omits
prefix checks. Otherwise it checks the long-prefix condition for
every item and adds twice the canonical comparison result.

The [preimage-length primitive](preimage-length.md) uses `OP_SIZE` on
one authenticated item. The [signature-budget experiment](../tapscript-budget-validation.md)
measures the actual full tapscript witness and budget in the execution
harness. The local predicate instead measures a standalone serialization
of the fixed suffix and does not read a transaction, script, control
block, annex, or other caller data. Scoped catalog, source, and PR
searches found no existing implementation of this suffix cap.

## Evidence and limits

At 32 four-byte items with a 161-byte cap, the tight leaf uses 199
script bytes and 146 executed non-push operations at peak 35. The exact
conditional baseline uses 487 bytes, 274 operations and peak 36. Both
use 161 serialized data bytes and zero hints. At the first exact cap for
the same count, the branch-free route saves 32 bytes but executes 32 more
operations when every item has a short prefix. See
[the matched comparison](../comparisons/witness-data-size.md) and
[the negative results](../negative-results/witness-data-size.md).

The [implementation README](../../src/support/witness_data_size/README.md)
lists all matched cases and reproducible tests. Evidence is
`locally-reproduced` and execution is `unclassified`. Tests check typed
limits in the local profiles, including the separate local Policy
item-size check. No funded spend or relay policy is classified.
