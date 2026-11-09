# Membership checks cannot substitute for exact multiplicity

Checking each right value against a left pool without consuming the
match permits `[A,A,A]` to match `[A,B,A]`: all right values occur in
the left pool, but the counts differ. The hinted contract test tries all
six in-range depth schedules for this counterexample and rejects every
one. Repeated equal byte strings remain distinct pool items.

Omitting hints also has a measured tradeoff. At width 16 the greedy
schedule lowers the witness from 124 to 97 bytes and the combined peak
from 50 to 34. It uses 1,477 script bytes and 599 executed non-push
operations, versus 219 and 151 for destructive hints. The same leaf
boundary checks exact multiset equality and terminal true in each case.
The two-invocation peak is 66 for greedy and 97 for hints, with
64 ordinary entry items and zero or 30 hints respectively. The hinted
approach needs a live-stack budget for every preloaded certificate.
Evidence is `locally-reproduced` and execution is `unclassified`.
See the [fixture and reproduction](../primitives/opaque-multiset.md).
