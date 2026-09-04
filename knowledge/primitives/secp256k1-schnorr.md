# Explicit secp256k1 Schnorr verification

## Question and objective

What does BIP340 verification cost when secp256k1 field relations must be
expressed explicitly in Script? Two boundaries are tracked: a compact
fixed-instance certificate whose generator performs public hashing and scalar
multiplication, and a check-signature-from-stack-style verifier whose message
and signature are hostile witness inputs.

## Spend-time CSFS construction

`csfs::verifier` fixes only the x-only public key. Witness data supplies the
message, `r`, `s`, the even affine `R.y`, and exact arithmetic hints. Script
computes the BIP340 tagged hash, proves `s<n`, binds `R.x=r`, validates
`R.y^2=r^3+7` and even parity, and checks `sG-eP=R`.

The two dynamic scalars use signed radix-256, position-specific fixed-base
tables. Affine inversions remain off chain: a general addition verifies the
hinted slope and derives its output with 2M+1S, while doubling uses 2M+2S. The
static complete transition shares the common slope product between its
general and tangent branches. Signed-table y negation is deterministic carry
normalization, not another witness relation. The top scalar digit is kept in
`[0,256]`, avoiding the missing-high-carry error of naïve 32-digit balanced
recoding.

For deterministic key `[3;32]`, message `[42;32]`, and the no-aux
libsecp256k1 signature, the policy-produced script is 8,292,228 unoptimized
bytes. Its serialized arithmetic/input witness is 81,740 bytes in 32,556
items, the relaxed execution peaks at 33,589 stack items, and the script has
4,593,240 static non-push opcodes. Valid and changed-message results agree with
the independent libsecp256k1 API, so acceptance behavior is
`differentially-validated`; execution remains `research-unlimited`: the
helper disables the stack limit, and the construction is known to violate
both the 1,000-item stack bound and transaction/block-weight feasibility.

Affine is smaller than projective on this boundary because the inversion is
already outsourced. Inspected mixed-Jacobian formulas cost roughly 7M+4S per
addition and 2M+5S per doubling before normalization and exception handling;
arbitrary `(X,Y,Z)` witness inputs also require nonzero-Z, curve,
normalization, affine-x, and parity proofs. GLV retains approximately the same
total fixed-position table/addition count after splitting both dynamic
scalars and adds decomposition constraints. Dynamic wNAF reduces executed
nonzero additions but not the number of conditional positions an unrolled
Script must authenticate. These are scoped cost-model results, not universal
lower bounds.

## A 2^32-leaf taptree lookup

One locally executed experimental leaf specializes the low 32 bits of `s`.
It embeds their precomputed signed generator contribution, checks the four
recoded digits against leaf constants, and removes four table selections and
four complete affine transitions. The representative leaf is 7,850,893 bytes,
441,335 bytes (5.32%) smaller than the ordinary CSFS leaf. Its arithmetic
witness is 77,869 bytes, another 3,871-byte reduction.

A depth-32 control block contributes 1,024 Merkle bytes and costs 1,026 more
serialized bytes than a depth-zero control block because its item length uses
a three-byte CompactSize. The net representative revealed-witness saving is
therefore 444,180 bytes after counting script, arithmetic witness, and control
path. The complete `2^32` tree was not built: naïve leaf material is estimated
at about 33.7 PB, so only the single-leaf delta is `locally-reproduced`; the
full-tree practicality claim is `inspected`. This trick does not resolve the
stack or block-weight violations.

## Fixed-instance construction

The generator parses `r || s`, enforces `x(P) < p`, `r < p`, and `s < n`, and
lifts both x coordinates to BIP340's even-y points. It derives the tagged-hash
challenge and public points `sG` and `eP`, then asks Script to certify
`R + eP = sG` through three affine slope identities.

Public scalar multiplication uses the secp256k1 GLV endomorphism and a reduced
lattice split. Two signed components of at most 129 bits are encoded with
width-5 wNAF and evaluated together in mixed Jacobian-affine coordinates. One
eight-entry odd-multiple table is built in Jacobian coordinates and
batch-normalized; multiplying every x coordinate by beta derives the second
table. This affects deterministic generator work, not locking-script opcode
count.

The Script schedule is one raw certified square for `lambda^2`, followed by a
two-product raw certified batch for the two remaining slope products. Every
hostile operand is first compared digit-for-digit with its instance constant.
Exact quotient/carry relations derive all results. The 58,596-byte complete
predicate uses a 1,039-byte/346-item witness and peaks at 882 combined stack
items. It is above the 32-KiB optimizer cutoff, so that measured size is
unoptimized by policy.

## Fixed-instance evidence and comparison

The result is `differentially-validated`: deterministic valid and invalid
instances agree with the libsecp256k1 API exposed by `rust-bitcoin`; GLV/wNAF
outputs agree with a separate affine double-and-add implementation; the beta
map agrees with multiplication by lambda; and strict local execution rejects
changed operands, quotient hints, and carry hints.

The raw-certified 2M/1S field core is 57,241 bytes. Replacing its square with a
third general product gives a 63,219-byte batch at a 993-item peak, while three
standalone general multipliers total 65,316 bytes. The retained schedule saves
5,978 bytes (9.5%) and 111 stack items against the all-general batch. These are
like-for-like field-proof boundaries; generator time is excluded from each.

## Fixed-instance trust and deployment boundary

This is an instance-specialized proof, not a spend-time replacement for
`OP_CHECKSIG`. The generated tapleaf commits to the public key, message, and
signature through its bound field constants. Challenge hashing, GLV
decomposition, precomputation, and scalar multiplication are trusted public
generator calculations. A party that does not trust leaf construction must
reproduce those calculations.

The arithmetic vocabulary is tapscript-compatible and the local interpreter
enforces the strict stack limit. No complete transaction has been checked
against Bitcoin Core, so deployment is `unclassified`; consensus and relay
validity are not claimed. Legacy and P2WSH size/opcode limits are exceeded.

See the [implementation README](../../src/signatures/schnorr/README.md), the
[signature comparison](../comparisons/signatures.md), the
[native field entry](secp256k1-field.md), negative results NR-026 through
NR-029, and OP-016.
