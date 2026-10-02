# Bitwise modulo-65,537 remainder loses to paired byte lanes

The [general binary Horner baseline](../../research/u32-fermat-residue/baseline.rs)
validates four canonical byte items, expands them into 32 bits with the existing
little-endian splitter, reverses consumption using the altstack, then applies
`r=2*r+bit` and subtracts 65,537 iff needed. Its intermediate remainder is at
most 131,073 and fits native ScriptNum arithmetic. It is semantically correct
under deterministic host-remainder vectors and the shared hostile-input suite.

For the identical `0x89abcdef` input/output boundary, it measures 1,137 optimized
fragment bytes, a 1,141-byte expected-residue leaf, 13 serialized data-witness
bytes across four items, **zero hints**, and a 35-item combined peak. The
[two-lane construction](../primitives/u32-mod65537.md) is 100/104 bytes with the
same witness and a 7-item peak. Static non-push counts are 684 versus 75;
dynamic executed-opcode counts are unavailable. All input items coexist at entry,
with no table or setup, and both generated scripts are below the optimizer cutoff.

The bitwise circuit is therefore dominated for the measured fixed-modulus
objective. It remains comparison-only code and a useful general remainder
reference; the result does not rule out bitwise processing when input bits are
already live or when a different modulus cannot use the two-lane identity.
No cryptographic, consensus or policy acceptance follows. Evidence is
`locally-reproduced`, deployment `unclassified`; exact artifacts and options are
in [the report](../../research/u32-fermat-residue/metrics.json).
