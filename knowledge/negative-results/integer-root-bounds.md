# NR-080: Root trial overhead, byte growth and the unsigned-word boundary

The residual-difference root schedule wins measured bytes at seven bits and
above, but loses at small widths: restoring/threshold fragments are 27/18 at
one or two bits, 48/34 at four and 72/70 at six. Threshold dispatch also uses
three peak items rather than five. Seven bits is the measured byte crossover:
98 versus 106 bytes. This is a byte/stack tradeoff, not universal
dominance or a new integer-root algorithm.

At 16 bits restoring is 232 bytes versus threshold 2,989 (both ALL), with one
ordinary data item, zero hints, the same five-byte canonical max-input witness,
and peaks five/three. At 24/31, threshold grows to 54,109/659,112 bytes,
explicitly unoptimized NONE, versus restoring 405/614 ALL. The local tapcontext
comparison does not make the huge threshold leaves legacy/P2WSH compatible.

Repeating a small ALL fragment does not imply an ALL whole script. At 996
preloaded 31-bit roots, whole raw fragment is 615,528 bytes and uses NONE;
the individually ALL-compiled component sum is 613,536, so whole-policy delta
+1,992 includes a policy difference. The checked leaf is 618,389 bytes
unoptimized; witness 2,738, ordinary inputs 996, hints zero, combined peak 1,000.
The 997th root fails StackSize at 1,001. All future inputs and parked outputs
share the limit. The allowed alias-inclusive witness maximum is 4,983 bytes;
canonical fixture bytes do not replace that encoding boundary.

Positive 2^31 needs five ScriptNum bytes and fails ScriptIntNumericOverflow
before a 31-bit root calculation. Root bits/difference intermediates fit the
four-byte domain, but that does not permit an unsigned 32-bit single-ScriptNum
input. A different checked word/limb representation is needed (OP-038).
Numeric aliases leave the same root; literal result checks also admit all
integers in the checked root interval. Root calculation is no authentication.

All results are locally-reproduced/unclassified under explicit stack-limited
local Consensus tapscript. No Core, transaction budget or relay acceptance is
claimed. See [source/artifact guide](../../research/integer-root-bounds/README.md)
and [primitive](../primitives/scriptnum-isqrt.md).

At 53 repeats the fragment still uses ALL (raw 32,754 / final 32,646), but
checking every result raises the leaf to raw/final 32,903 and switches it to
unoptimized NONE. The raw predicate increment is 149, while final increment
is 257. Data items 53 / hints zero / witness 142 / peak 57 are unchanged.
Thus a fragment's optimization status is not a complete leaf's status.
