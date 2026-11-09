# A full length-keyed digest table can exhaust the stack

A 521-entry table materializes every digest to verify just one
opening. The selected operation peaks at 523 combined items before
caller state. With 477 preserved caller items it accepts at exactly
1,000. With 478, it fails with `StackSize`. The eight-entry block
schedule accepts that same one-preimage witness with 478 caller items
and verifies the same length/digest relation.

A single length also cannot distinguish two desired digests for
different preimages of the same size. In the tested map, changing
the bytes while keeping the length selects the same slot and fails
its digest comparison. See the
[checked schedules](../../src/commitments/length_keyed/README.md).
Evidence is `locally-reproduced`; execution is `unclassified`.
