# Pinned-start checkpoint chains

**Question:** Can one native SHA-256 check exclude the deterministic first-bit
substitution in a streamed mixed-hash chain without extra data or hint items?
**Hypothesis:** Pinning the actual starting bytes excludes the substitution;
a length-only check does not. Compare the same honest opening and terminal
predicate under unbound, length-only, and pinned-start scripts. Treat every
witness item as hostile, with public checkpoint order and widths fixed by the
leaf, canonical tapscript IF selectors, and at most 1000 combined stack items.

[The wrapper](../../src/commitments/hash_path/README.md#pinned-starting-state-and-streamed-checkpoints)
reuses the existing unary hash path. It verifies `SHA256(x)` before consuming
selectors and checks each public digest before feeding the resulting state into
the next round. No checkpoint preimages or hints are supplied separately.

| Honest 4+3-bit opening | Script bytes | Data / complete witness bytes | Data / hint items | Peak | Executed non-push ops | Weight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Unbound | 80 | 46 / 161 | 8 / 0 | 8 | 36 | 539 |
| Length-only | 84 | 46 / 165 | 8 / 0 | 10 | 38 | 543 |
| Pinned start | 116 | 46 / 197 | 8 / 0 | 10 | 39 | 575 |

The pin adds 36 bytes and three executed operations relative to the identical
honest unbound case. The 997-selector cases both peak at 1000 with 998 data
items and zero hints; their complete witnesses are 6113 and 7110 bytes for
zeroes and ones. The complete-transaction boundary and budget/opcode trace
are detailed in the README. The [pinned Core report](../../tests/data/pinned-hash-path-v30.3.json)
records twelve cases: the honest controls, both accepted substitutions, the
pinned rejection, changed checkpoint, reordered rounds, nonminimal selector,
997-bit boundaries and one extra live item. The accepted transactions were
mined and admitted by the pinned policy, so those configurations are
`policy-validated` and their verdicts `differentially-validated`; dynamic counts
and budget traces are `locally-reproduced`. The general API is `unclassified`.

The result only excludes the demonstrated substitution. The 160-bit mixed
chain has no general binding proof, the leaf does not bind participants or
transactions, and checkpoint concatenation does not give cryptographic domain
separation. The retained-bit Lamport/Binohash consumer remains
[OP-020](../open-problems.md#op-020--bound-start-hash-paths-and-binohash-composition).
