# Non-cryptographic arithmetic checksums

The comparison asks whether deferring both Adler-32 reductions improves
script size under a canonical-byte/two-residue-output contract. RFC 1950
already describes delayed reduction; the local contribution is bounded
ScriptNum reduction and separation of input validation from accumulator
lifetimes. Source/cost bindings and reproduction commands are in the
[research guide](../../research/adler32-delayed-reduction/README.md).

All fixtures are n copies of canonical ScriptNum 255, all n ordinary data
items coexist at entry, and every row has exactly **zero hint items**.
Fragment bytes include range/canonicality checks, input staging, arithmetic
and reduction. Leaves add B/A equality predicates and TRUE. Input pushes,
leaf/control-block witness serialization and transaction costs are excluded.
Standalone peaks count both stacks; caller state must be added.

| n | Deferred fragment / leaf | Prefix-bounded streaming fragment / leaf | Data witness bytes / items | Peak both schedules | Compiler policy |
| ---: | ---: | ---: | ---: | ---: | --- |
| 0 | 2 / 1 | 2 / 1 | 1 / 0 | Fragment 2, leaf 1 | ALL / ALL |
| 1 | 21 / 30 | 21 / 30 | 4 / 1 | 4 | ALL / ALL |
| 32 | 636 / 645 | 740 / 749 | 97 / 32 | 35 | ALL / ALL |
| 128 | 2512 / 2521 | 3812 / 3821 | 385 / 128 | 131 | ALL / ALL |
| 512 | 9864 / 9874 | 19428 / 19438 | 1539 / 512 | 515 | ALL / ALL |
| 808 | 15531 / 15540 | 32748 / 32757 | 2427 / 808 | 811 | ALL / ALL |
| 809 | 15550 / 15559 | 32793 / 32802 | 2430 / 809 | 812 | Deferred ALL; streaming NONE (unoptimized) |
| 997 | 19122 / 19132 | 41253 / 41263 | 2994 / 997 | 1000 | Deferred ALL; streaming NONE (unoptimized) |

The streaming baseline already omits reductions unreachable under early
prefix bounds, so the 104-byte n32 saving is against a stronger comparison
than naive always-normalized streaming (1,442 fragment bytes). Large rows
explicitly follow different policy paths; this is a final policy-produced size
comparison, not an ALL-versus-ALL extrapolation. At n728 naive streaming's
raw fragment is 32,762 bytes (ALL) and raw leaf 32,773 (NONE), demonstrating
why fragment and leaf flags must be recorded independently even when
optimization does not change either final length.

Interleaved validation reaches the same n32 bytes but peak 37 instead of 35.
Its n995 leaf accepts at peak 1,000; n996/997 reject at first peak 1,001.
Prevalidating n997 accepts at 1,000 with unchanged fragment byte count.
All accepted rows are local tapscript (`locally-reproduced`, `unclassified`),
with strict resource checks and OP_CAT disabled. No Core spend or relay-policy
evidence is inferred. Static non-push counts are artifact-bound; executed
non-push counts remain unknown. Signature validation weight charged is zero.

These checksums cannot replace hash commitments or authentication. The
documented three-byte collision survives both schedules by design. The
two residues also do not supply the packed network-order checksum or a
general incremental-state API. All those costs and semantics are separate.
