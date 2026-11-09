# An ascent count alone accepts multiple turns

The signed sequence `[0,2,1,3,0]` has two ascents and ends
with a descent. A scan that rejects equal adjacent values and
counts ascents, but omits the phase check, returns index two.
The sequence has two peaks and fails the
[checked verifier](../../src/arithmetic/single_peak/README.md).

The ascent count gives a peak index only once all ascents are
known to precede all descents in the original sequence.
See the [matched comparison](../comparisons/signed-single-peak.md).
Evidence is `locally-reproduced`. Execution is `unclassified`.
