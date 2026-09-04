# Explicit secp256k1 Schnorr verification

This module contains two deliberately different research boundaries:

- `hinted_verify` certifies one public-key/message/signature instance fixed
  before leaf generation.
- `csfs::verifier` commits only to the x-only public key. The 32-byte message,
  `r`, `s`, supplied even nonce y-coordinate, and arithmetic hints are hostile
  witness data. It computes the BIP340 challenge and checks `sG - eP = R` in
  Script, matching check-signature-from-stack semantics rather than replacing
  transaction-context `OP_CHECKSIG`.

## Spend-time CSFS research verifier

The witness encodes `r`, `s`, and the message as nine unsigned 29-bit limbs
each. Since `r` is already `R.x`, it supplies only `R.y` as 29 balanced field
digits rather than redundantly supplying an uncompressed `R`. Script proves
`R.y` canonical, checks `R.y^2 = r^3 + 7`, and enforces even parity. It also
proves `s < n`; `r < p` follows from converting and certifying it as a field
element. The public key is fixed by the leaf and lifted to its even BIP340
point when the leaf is generated.

The verifier constructs
`SHA256(tagHash || tagHash || r || P || message)` from witness limbs and uses
the full 256-bit digest as the challenge scalar. Explicit reduction modulo `n`
is unnecessary for multiplication by a point of order `n`. Two fixed-base,
signed radix-256 scalar multiplications use 32 position-specific tables per
base. The lower 31 digits lie in `[-128,127]`; the top digit remains in
`[0,256]` so the recoding covers every 256-bit value without an omitted carry.
Negative table points are derived deterministically as `(x,p-y)` in balanced
radix 512.

Affine slope inversions are performed off chain. Script verifies the supplied
slope through multiplication identities and derives the next point. A general
addition executes two products and one square; doubling executes two products
and two squares. The complete static transition shares its expensive slope
product between those branches, combines the two x-coordinate subtractions in
one exact carry relation, and verifies `3*x^2` with one scaled relation.

Metrics below use key `[3;32]`, message `[42;32]`, and libsecp256k1's
deterministic no-aux-randomness signature. They are reproduced by the ignored
`signature_is_witness_data_and_validates_end_to_end` test. The locking script
is above the 32-KiB optimizer cutoff, so the policy-produced size is
unoptimized.

| Configuration | Locking script | Arithmetic/input witness | Witness items | Maximum stack items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Width-8 signed affine CSFS | 8,292,228 bytes | 81,740 bytes | 32,556 | 33,589 | 4,593,240 |

Valid and changed-message outcomes agree with the libsecp256k1 API exposed by
`rust-bitcoin`, so acceptance behavior is `differentially-validated`.
This successful execution is `research-unlimited`: the helper runs in a
tapscript context with the combined stack limit disabled. The construction is
known to exceed the 1,000-item stack rule, and the revealed script alone also
cannot fit within a Bitcoin block's weight limit. It is therefore not a
deployable tapscript despite using tapscript opcodes.

### Why wNAF, GLV, and projective coordinates do not win here

Those techniques materially accelerate the fixed-instance host generator
below, but their usual CPU-cost argument does not transfer automatically to a
dynamic Script verifier. GLV splits each of the two dynamic 256-bit scalars
into two roughly 128-bit scalars: at a fixed window width it retains roughly
the same total number of position/table entries and additions, then adds
decomposition/sign constraints. A dynamic wNAF stream reduces executed
nonzero additions, but an unrolled Script must still contain conditional
addition logic at every possible bit position or authenticate a compressed
position list. Neither is smaller than the retained fixed-position window
layout under the current gate costs.

Projective coordinates remove inversions that this verifier never computes on
chain: the affine slope is a hint, and one product binds it to its numerator
and denominator. Representative mixed-Jacobian formulas require about 7M+4S
per addition and Jacobian doubling about 2M+5S, before exceptional-case and
normalization checks, versus affine 2M+1S and 2M+2S. An arbitrary witness
`(X,Y,Z)` also needs nonzero-`Z`, curve, normalization, affine-x, and even-y
proofs. Projective state may still win if a surrounding protocol already
authenticates it; it is dominated for this standalone hostile-hint boundary.
These projective counts are an inspected cost-model comparison, not a locally
implemented projective CSFS row.

### A 2^32-leaf Taproot lookup table

`csfs::verifier_with_generator_low32_leaf` implements one leaf of the proposed
gigantic taptree. Each conceptual leaf commits to one value of the low 32 bits
of `s`, embeds their precomputed signed fixed-base contribution, checks the
four recoded scalar digits against leaf constants, and omits four table
selections and four complete affine transitions. A balanced tree with all
`2^32` values has depth 32.

For the deterministic row above, the specialized leaf is 7,850,893 bytes,
saving 441,335 locking-script bytes (5.32%). Its arithmetic/input witness is
77,869 bytes, saving another 3,871 bytes. Relative to a depth-zero control
block, a depth-32 control block adds 1,024 Merkle-proof bytes and crosses the
CompactSize threshold: 1,026 additional serialized bytes. Counting the
revealed script, arithmetic witness, and that control-path delta gives a net
444,180-byte saving for the representative spend.

Only the representative leaf was constructed and executed locally. The full
tree is an inspected extrapolation: naïvely materializing `2^32` scripts of
roughly 7.85 MB is about 33.7 PB of leaf material, plus billions of hashes. The
Taproot output commits only one root and a spend reveals only one path, but
root generation and data availability make this a thought experiment. It also
does not cure the stack or block-weight violations. Specializing another
independent 32-bit chunk in the same lookup would require a `2^64` Cartesian
leaf space unless another commitment structure is introduced.

## Fixed-instance parameters

- Public key: one BIP340 32-byte x-only secp256k1 encoding.
- Message: exactly 32 bytes, as required by BIP340.
- Signature: exactly 64 bytes, parsed as `r || s`.
- Scalar window: width-5 signed non-adjacent form (wNAF).
- Curve engine: secp256k1 GLV split with the beta endomorphism, mixed
  Jacobian-affine accumulation, and batched normalization of odd multiples.
- Field engine: ordinary-domain balanced radix-512 bigint9.

`hinted_verify` rejects `x(P) >= p`, `r >= p`, `s >= n`, and x coordinates
that do not lift to curve points with even y. It derives
`e = tagged_hash("BIP0340/challenge", r || P || m) mod n`, computes `sG` and
`eP`, then emits the field proof.

## Fixed-instance optimization design

The public scalar multiplications use the reduced secp256k1 GLV lattice to
split a 256-bit scalar into two signed components of at most 129 bits. Each
component uses width-5 wNAF. One eight-entry table of odd multiples is built in
Jacobian coordinates and batch-normalized with Montgomery's trick; applying
`(x,y) -> (beta*x,y)` derives the lambda-component table without another point
precomputation. The two wNAF streams are interleaved in one mixed-Jacobian
accumulator.

The Script proof uses the affine slope lambda. It checks
`lambda*(x(eP)-r) = y(eP)-y(R)`,
`lambda^2 = x(sG)+r+x(eP)`, and
`lambda*(r-x(sG)) = y(sG)+y(R)`. The two general products share one table; the
middle equation uses the materially smaller specialized square gate first.
This schedule is smaller than the three-general-product batch and reduces the
strict stack peak from 993 to 882 items.

On the raw-operand-certified arithmetic boundary, the retained 2M/1S core is
57,241 bytes. A three-general-product shared batch is 63,219 bytes, so square
specialization saves 5,978 bytes (9.5%); three independent standalone
multipliers are 65,316 bytes, making the retained core 8,075 bytes (12.4%)
smaller. The complete 58,596-byte row below additionally binds every hostile
operand to the fixed instance and checks all three outputs.

## Fixed-instance script metrics

Metrics use a deterministic key `[3;32]`, message `[42;32]`, and libsecp256k1
no-aux-randomness signature. They describe a complete terminal predicate and
its full serialized arithmetic witness. The generated script is above the
32-KiB optimizer cutoff and is therefore unoptimized by repository policy.

| Configuration | Locking script | Unlocking witness | Witness items | Maximum stack items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| GLV/wNAF/Jacobian generator + 2M/1S field proof | <!-- metric:secp256k1_schnorr_script -->58596<!-- /metric:secp256k1_schnorr_script --> bytes | <!-- metric:secp256k1_schnorr_witness -->1039<!-- /metric:secp256k1_schnorr_witness --> bytes | <!-- metric:secp256k1_schnorr_witness_items -->346<!-- /metric:secp256k1_schnorr_witness_items --> | <!-- metric:secp256k1_schnorr_stack -->882<!-- /metric:secp256k1_schnorr_stack --> | <!-- metric:secp256k1_schnorr_opcodes -->37323<!-- /metric:secp256k1_schnorr_opcodes --> |

The boundary is `complete-leaf:` fixed-instance operand binding, raw operand
certification, one specialized square, two shared-table multiplications,
output comparisons, witness cleanup, and a clean terminal true; it excludes
tapleaf/control-block serialization, transaction context, and Bitcoin Core
validation. Public challenge hashing, GLV decomposition, precomputation, and
scalar multiplication happen in the deterministic generator and are not
Script opcodes.

## Fixed-instance security

All 346 witness items are hostile. Script binds each multiplication/square
operand to the fixed generated instance before exact reduction checks, and the
field backend derives rather than trusts each result. Corrupting operands,
quotients, or carries fails. BIP340 range checks and even-y lifts are applied
before generation. The optimized curve engine is tested against a separate
affine double-and-add implementation, its endomorphism is checked against
multiplication by lambda, and valid/invalid results are compared with the
libsecp256k1 API re-exported by `rust-bitcoin`.

The critical trust boundary is instance specialization: correctness assumes
the generator faithfully computed SHA-256, `sG`, and `eP`. A party that does
not trust leaf generation must reproduce those public calculations. A spend-
time signature verifier should use tapscript `OP_CHECKSIG` instead.

## Fixed-instance script compatibility and standardness

The generated opcodes are tapscript-compatible, and local strict
`bitcoin-scriptexec` tests enforce the 1,000-item combined-stack limit. The
script has not been placed in a complete transaction or validated against a
pinned Bitcoin Core node. Evidence is therefore `differentially-validated`
for arithmetic/acceptance behavior and deployment remains `unclassified`, not
a consensus or relay-policy claim. Legacy and P2WSH size/opcode limits are
exceeded.

## Fixed-instance witness and stack contract

The witness is `G1 | G0 | S`, bottom to top. Each `G` is
`lhs[28..0] | rhs[28..0] | q[10..0] | carry[55..0]`; `S` is
`lambda[28..0] | q[10..0] | carry[55..0]`. Digit/carry zero is nearest the
top within its vector. The square consumes `S` while preserving both `G`
groups, then the two-product batch consumes `G0` followed by `G1`. The script
leaves exactly one truthy stack item.

## Fixed-instance operational notes

Malformed public encodings compile to a rejecting predicate with no arithmetic
witness. Extremely rare affine infinity/zero-denominator instances also use an
explicit fixed outcome because the ordinary slope certificate is undefined;
the common measured path always uses the three field relations. Generated
field scripts must continue to use
`support::script::ScriptCompilation::compile_with_policy()`.

Supplying the public key and nonce as full affine `(x,y)` points does not reduce
this fixed-instance Script: the generator already performs BIP340's even-y
lifts and promotes each point internally as `(x,y,1)` for Jacobian work.
Supplying arbitrary Jacobian `(X,Y,Z)` points would add nonzero-`Z`, affine-x,
curve, normalization, and normalized-y parity obligations. It is useful as an
internal accumulator representation, but dominated as an untrusted public
input on this boundary.
