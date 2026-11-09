# Runtime rotation limits and aliases

Copying selected items keeps the entire original vector live while
the output vector grows. Its peak is `max(n+4, 2*n+2)` plus preserved
caller state. The exact local tests accept width 499 at peak 1,000
and reject width 500. Destructive selection instead peaks at `n+4`
because the source count shrinks as the output count grows.

Canonical range checking is part of the offset contract. Treating
the offset as an arbitrary modular residue would permit `k=n` as
another encoding of the identity. The actual fragment rejects `n`,
negative offsets, and noncanonical zero before routing.

Even canonical offsets can have the same output when payloads are
periodic. Offsets 0 and 2 both preserve `[a,b,a,b]`, and both pass the
same output check in the focused test. A consumer that requires
a specific offset must bind it separately.

The [matched fixture](../../src/support/rotation/README.md#script-metrics)
compares the same outputs with identical terminal predicates.
Evidence is `locally-reproduced`; execution is `unclassified`.
