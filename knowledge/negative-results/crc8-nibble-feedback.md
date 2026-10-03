# NR-081: CRC-8 nibble feedback trades startup and stack for code growth

Evidence: `locally-reproduced`; deployment: `unclassified`.
Question: does sixteen-entry feedback improve CRC-8 with matched hostile
numeric-nibble input and canonical output boundaries?

The feedback table plus shared triangular XOR state needs 184 resident items.
At one byte its 414-byte fragment loses to the serial bit register's 285;
at two bytes it wins 520 versus 541, and at nine wins 1,262 versus 2,333.
Serial needs N+13 combined items versus feedback N+188. These figures include
the same ranges, message, setup, cleanup and byte packing; checked leaves add
the same exact-CRC predicate. The empty case optimizes to one zero fragment
byte and one TRUE leaf byte; a zero checksum is not a true bare predicate.

All data are ordinary numeric nibbles at entry, with zero hint items per
invocation and cumulatively. Feedback accepts 406 complete bytes (812 data /
zero hints) at peak 1,000; its unoptimized NONE fragment/leaf are
43,345/43,349. The private serial frontier admits 987 nibbles at 1,000, but
that odd half-byte stream is not a public complete message. The complete-byte
frontier is 493 bytes, 986 data / zero hints, peak 999. Neither result is Core
or relay validation. Public construction rejects 407 bytes before generation.

Nine-byte independent repeated calls reinstall their tables. R=25 gives
31,550/31,638 with ALL; R=26 gives 32,890/32,982 with unoptimized NONE. The
component-policy delta changes from -50 to +26, including the policy cutoff.
At R=45 all 810 inputs coexist with state and parked outputs at peak 998;
only two caller items remain. R=46 overflows at measured 1,001. Zero hints
do not make the 184-item resident memory or the future inputs disappear.

Canonical-input siblings are distinct contracts, not a free upgrade of numeric
rows. Their explicit encoding guard changes script costs and their ALL/NONE
cutoff; raw aliases are rejected as EqualVerify under Consensus and as
MinimalData under the local Policy subset. Canonical domain encoding caps are
recorded; an attained witness maximum under a fixed checksum is not claimed.

The frozen prototype also retains its first private serial reference error:
an extra feedback copy produced five output items for a zero nibble. The same
exact-result assertion detects its original-step mutation after the corrected
one-item control passes. This was a construction-time reference error, not a
production regression. Compiled hostile range/canonical/terminal bypasses are
separate tests with typed errors, valid controls and exact cleanup.

Source and reproduction: [research](../../research/crc8-nibble-feedback/README.md),
[primitive](../primitives/crc8-smbus.md),
[metrics](../../research/crc8-nibble-feedback/metrics.json).
The wider byte/stack target remains [OP-039](../open-problems.md#op-039--streamed-crc-8-frontier).
