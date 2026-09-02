# Residue-number arithmetic

Two residue-number designs are available: the original five-coordinate
prime-power lookup design and a 75-coordinate prime-only design whose
multiplication uses discrete-logarithm and exponent tables.

## Original lookup RNS

### Parameters

- Moduli/default: `[4, 9, 25, 7, 11]`.
- Combined modulus: `69,300`; representation width: five residues.
- Addition/subtraction table size: 107 items each.
- Multiplication table size: 892 items.
- Both add/sub operands use ordinary residues. Multiplication requires the left
  operand in indexed-row form and the right operand in ordinary form.

### Script metrics

Each size includes table setup, the operation, table cleanup, and moving the
five results back from the altstack. Operand pushes and final verification are
excluded. Both operands together occupy ten witness items when witness-supplied.

| Operation | Locking fragment | Maximum stack items |
| --- | ---: | ---: |
| Add | <!-- metric:rns_add -->219<!-- /metric:rns_add --> bytes | 118 |
| Subtract | <!-- metric:rns_sub -->221<!-- /metric:rns_sub --> bytes | 118 |
| Multiply | <!-- metric:rns_mul -->1564<!-- /metric:rns_mul --> bytes | 903 |

## Prime-only 256-bit-product RNS

### Parameters

The `rns::prime` profile is optimized for the exact product of two unsigned
256-bit integers. It uses 75 prime coordinates: `2`, then every odd prime
through `383` except `47`. Their product has 513-bit bitlength and
`log2(M) = 512.063700...`, so

```text
M > (2^256 - 1)^2.
```

Thus one 256-by-256-bit product cannot wrap. Arithmetic is still modulo the
composite `M`; longer expressions need a separately proved bound. For example,
`a*b + c` remains below `M` for unsigned 256-bit `a`, `b`, and `c`, while the
sum of two full-width products does not have that guarantee.

All public arithmetic keeps canonical residues in `0..p-1`. Centered
add/subtract remains available for comparison, using a canonical bit for the
modulus-2 coordinate and `[-(p-1)/2, (p-1)/2]` elsewhere.

### Arithmetic metrics

Sizes include the operation and moving its 75 outputs back from the altstack.
Operand pushes, range checks, and a terminal predicate are excluded. Peaks
include both 75-item operands and count the main and alt stacks together.

| Encoding | Operation | Locking fragment | Maximum stack items |
| --- | --- | ---: | ---: |
| Canonical | Add | <!-- metric:prime_rns_add -->1134<!-- /metric:prime_rns_add --> bytes | <!-- metric:prime_rns_add_stack -->151<!-- /metric:prime_rns_add_stack --> |
| Canonical | Subtract | <!-- metric:prime_rns_sub -->1140<!-- /metric:prime_rns_sub --> bytes | <!-- metric:prime_rns_sub_stack -->151<!-- /metric:prime_rns_sub_stack --> |
| Centered | Add | <!-- metric:prime_rns_centered_add -->1862<!-- /metric:prime_rns_centered_add --> bytes | <!-- metric:prime_rns_centered_add_stack -->151<!-- /metric:prime_rns_centered_add_stack --> |
| Centered | Subtract | <!-- metric:prime_rns_centered_sub -->1936<!-- /metric:prime_rns_centered_sub --> bytes | <!-- metric:prime_rns_centered_sub_stack -->151<!-- /metric:prime_rns_centered_sub_stack --> |
| Canonical | Multiply | <!-- metric:prime_rns_mul -->15628<!-- /metric:prime_rns_mul --> bytes | <!-- metric:prime_rns_mul_stack -->183<!-- /metric:prime_rns_mul_stack --> |

Canonical add/sub needs one conditional correction per odd prime. Centered
add/sub needs upper and lower corrections, so it has the same peak but a larger
locking fragment. This is why multiplication accepts and returns canonical
residues even though some private table entries are centered.

The residue encodings of `2^256-1` and `2^256-2` serialize to
<!-- metric:prime_rns_mul_witness -->332<!-- /metric:prime_rns_mul_witness -->
witness bytes for their 150 residue elements alone; the maximum over any two
canonical residue vectors is
<!-- metric:prime_rns_mul_witness_max -->391<!-- /metric:prime_rns_mul_witness_max -->
bytes. Both exclude the tapscript, control block, and terminal predicate.

### Multiplication design

`mul` generates both a streamed lookup candidate and a table-free binary
Horner candidate for each coordinate, then keeps the shorter compiled script.
Tables therefore never coexist, and many larger-prime coordinates need no
table at all:

1. Modulo 2 uses `OP_BOOLAND` and modulo 3 uses a table-free equality formula.
2. Plain and centered-multiplier binary Horner queries destructively decompose
   one canonical operand and perform modular doubling and conditional addition
   without witness hints.
3. Where a lookup remains shorter, small primes use full canonical
   discrete-log/exponent tables; other primes use signed-magnitude logarithms
   and half-exponent entries.

For `p=2h+1`, a positive magnitude has
`log_g(m) = L + b*h`. The table stores `L` with sign `b`; the query adds two
absolute values modulo `h` and XORs the token signs, input signs, and reduction
carry. For the unbiased encoding, negative zero cannot occur because
`log_g(m)=h` implies `m=-1=p-1`, outside the positive-magnitude interval
`1..=h`. The exhaustive affine-bias search rejects any shifted candidate that
would encode its unique zero-magnitude token with a negative sign.

Each coordinate also has a fixed affine bias `c`. It stores
`L'=(L+c) mod h`, folds the wrap into the sign bit, and shifts exponent entry
`r` to `g^(r-2c)`. This changes no query opcodes but reduces serialized table
literals. Generators and biases were exhaustively searched per fixed prime.
The final log and exponent accesses use destructive `OP_ROLL`s, allowing two
fewer table items to be cleaned up. Table setup and cleanup live wholly inside
the nonzero branch, so the zero path remains stack-balanced.

The completed multiplication fragment contains
<!-- metric:prime_rns_mul_opcodes -->10931<!-- /metric:prime_rns_mul_opcodes -->
static non-push opcodes.

The locking-script total is split by exact compiled origin, rather than
treating every byte as a per-product query cost:

| One-shot component | Bytes |
| --- | ---: |
| Table-entry pushes | <!-- metric:prime_rns_mul_table_push -->392<!-- /metric:prime_rns_mul_table_push --> |
| Destructive table cleanup | <!-- metric:prime_rns_mul_table_drop -->153<!-- /metric:prime_rns_mul_table_drop --> |
| Arithmetic, routing, and 75-output restoration | <!-- metric:prime_rns_mul_computation -->15083<!-- /metric:prime_rns_mul_computation --> |
| **Total** | **15,628** |

Thus lookup-memory lifecycle is 545 bytes, or about 3.5% of the one-shot
fragment. Concatenating ordinary `mul` fragments does not automatically
amortize those bytes: each fragment streams and destructively consumes its own
tables.

`prime::batch::mul` provides an executable coordinate-major alternative. It
keeps one coordinate table live while processing the whole batch, then drops
it before advancing. Generation reselects table versus binary Horner for the
requested batch size. For the maximum strict-stack batch of six products:

| Six-product batch component | Bytes |
| --- | ---: |
| Table-entry pushes | <!-- metric:prime_rns_mul_batch_6_table_push -->25510<!-- /metric:prime_rns_mul_batch_6_table_push --> |
| Full table cleanup | <!-- metric:prime_rns_mul_batch_6_table_drop -->6521<!-- /metric:prime_rns_mul_batch_6_table_drop --> |
| Arithmetic queries | <!-- metric:prime_rns_mul_batch_6_arithmetic -->30229<!-- /metric:prime_rns_mul_batch_6_arithmetic --> |
| Operand routing and result-to-altstack | <!-- metric:prime_rns_mul_batch_6_routing -->2202<!-- /metric:prime_rns_mul_batch_6_routing --> |
| **Raw batch fragment** | **<!-- metric:prime_rns_mul_batch_6_raw -->64462<!-- /metric:prime_rns_mul_batch_6_raw -->** |
| Restore all 450 outputs to main stack | <!-- metric:prime_rns_mul_batch_6_output_restore -->450<!-- /metric:prime_rns_mul_batch_6_output_restore --> |
| **Comparable returned-output total** | **<!-- metric:prime_rns_mul_batch_6 -->64912<!-- /metric:prime_rns_mul_batch_6 -->** |

That is 10,819 bytes per product after amortization, versus 15,628 bytes for
each independent one-shot fragment: 64,912 versus 93,768 bytes for six, a
30.8% reduction. The reproduced combined-stack peak is
<!-- metric:prime_rns_mul_batch_6_stack -->900<!-- /metric:prime_rns_mul_batch_6_stack -->
items. Seven products already require 1,050 operand items, so they cannot enter
the current 1,000-item-limited fragment. The batch metric assumes operands are
already supplied coordinate-major and outputs may remain coordinate-major;
conversion from existing vector-major state is excluded and can erase the
savings.

### Witness-hinted modular reduction

`mul_mod_hinted` verifies `a*b = q*N + r` for a positive, generation-time
modulus `N` of at most 256 bits. It consumes five canonical RNS vectors in the
order `lhs | rhs | quotient | remainder | remainder_complement`, where the
complement is `N - 1 - r`, and returns the remainder vector. Quotient,
remainder, and complement are public derived hints.

The measured secp256k1-field instance uses
`N = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`:

| Fragment | Locking script | Measured witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| 75-prime, no relation carries | <!-- metric:prime_rns_hinted_mod_mul -->25777<!-- /metric:prime_rns_hinted_mod_mul --> bytes | <!-- metric:prime_rns_hinted_mod_mul_witness -->477<!-- /metric:prime_rns_hinted_mod_mul_witness --> bytes | <!-- metric:prime_rns_hinted_mod_mul_stack -->384<!-- /metric:prime_rns_hinted_mod_mul_stack --> |
| 42-prime, exact carries, external bindings | <!-- metric:prime_rns_carry_hinted_mod_mul -->10952<!-- /metric:prime_rns_carry_hinted_mod_mul --> bytes | <!-- metric:prime_rns_carry_hinted_mod_mul_witness -->301<!-- /metric:prime_rns_carry_hinted_mod_mul_witness --> hint bytes | <!-- metric:prime_rns_carry_hinted_mod_mul_stack -->231<!-- /metric:prime_rns_carry_hinted_mod_mul_stack --> |
| 47-prime, exact carries, standalone global bindings | <!-- metric:prime_rns_bound_carry_hinted_mod_mul -->51055<!-- /metric:prime_rns_bound_carry_hinted_mod_mul --> bytes | <!-- metric:prime_rns_bound_carry_hinted_mod_mul_witness -->868<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_witness --> bytes for all 299 inputs | <!-- metric:prime_rns_bound_carry_hinted_mod_mul_stack -->305<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_stack --> |
| 46-prime, exact carries, composable certified operands | <!-- metric:prime_rns_composable_hinted_mod_mul -->31281<!-- /metric:prime_rns_composable_hinted_mod_mul --> bytes | <!-- metric:prime_rns_composable_hinted_mod_mul_witness -->471<!-- /metric:prime_rns_composable_hinted_mod_mul_witness --> incremental hint bytes; operands excluded | <!-- metric:prime_rns_composable_hinted_mod_mul_stack -->267<!-- /metric:prime_rns_composable_hinted_mod_mul_stack --> |

Their exact one-shot locking-script attribution is:

| Fragment | Table pushes | Table drops | Computation, validation, and routing | Total |
| --- | ---: | ---: | ---: | ---: |
| 75-prime, no carries | <!-- metric:prime_rns_hinted_mod_mul_table_push -->123<!-- /metric:prime_rns_hinted_mod_mul_table_push --> | <!-- metric:prime_rns_hinted_mod_mul_table_drop -->60<!-- /metric:prime_rns_hinted_mod_mul_table_drop --> | <!-- metric:prime_rns_hinted_mod_mul_computation -->25594<!-- /metric:prime_rns_hinted_mod_mul_computation --> | 25,777 |
| 42-prime, exact carries | <!-- metric:prime_rns_carry_hinted_mod_mul_table_push -->0<!-- /metric:prime_rns_carry_hinted_mod_mul_table_push --> | <!-- metric:prime_rns_carry_hinted_mod_mul_table_drop -->0<!-- /metric:prime_rns_carry_hinted_mod_mul_table_drop --> | <!-- metric:prime_rns_carry_hinted_mod_mul_computation -->10952<!-- /metric:prime_rns_carry_hinted_mod_mul_computation --> | 10,952 |
| 47-prime, globally bound exact carries | <!-- metric:prime_rns_bound_carry_hinted_mod_mul_table_push -->0<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_table_push --> | <!-- metric:prime_rns_bound_carry_hinted_mod_mul_table_drop -->0<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_table_drop --> | range <!-- metric:prime_rns_bound_carry_hinted_mod_mul_range_checks -->1060<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_range_checks --> + binding <!-- metric:prime_rns_bound_carry_hinted_mod_mul_residue_binding -->38801<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_residue_binding --> + relation <!-- metric:prime_rns_bound_carry_hinted_mod_mul_modular_relation -->10794<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_modular_relation --> + routing <!-- metric:prime_rns_bound_carry_hinted_mod_mul_routing_output -->400<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_routing_output --> | 51,055 |
| 46-prime, composable certified operands | <!-- metric:prime_rns_composable_hinted_mod_mul_table_push -->0<!-- /metric:prime_rns_composable_hinted_mod_mul_table_push --> | <!-- metric:prime_rns_composable_hinted_mod_mul_table_drop -->0<!-- /metric:prime_rns_composable_hinted_mod_mul_table_drop --> | validation <!-- metric:prime_rns_composable_hinted_mod_mul_validation -->444<!-- /metric:prime_rns_composable_hinted_mod_mul_validation --> + quotient binding <!-- metric:prime_rns_composable_hinted_mod_mul_quotient_binding -->9852<!-- /metric:prime_rns_composable_hinted_mod_mul_quotient_binding --> + remainder binding <!-- metric:prime_rns_composable_hinted_mod_mul_remainder_binding -->9664<!-- /metric:prime_rns_composable_hinted_mod_mul_remainder_binding --> + relation <!-- metric:prime_rns_composable_hinted_mod_mul_modular_relation -->10799<!-- /metric:prime_rns_composable_hinted_mod_mul_modular_relation --> + routing <!-- metric:prime_rns_composable_hinted_mod_mul_routing_output -->522<!-- /metric:prime_rns_composable_hinted_mod_mul_routing_output --> | 31,281 |

Only 183 bytes, 0.7%, of the no-carry verifier are table lifecycle. The carry
verifier has no lookup memory at all: its 10,952 bytes consist of 9,595 bytes
of arithmetic and exact relation checks, 979 bytes of canonical/complement
validation, and 378 bytes of routing and output handling. Repeating that
fragment therefore exposes no table setup to amortize; batching must instead
share external bindings or introduce a different arithmetic strategy.

The standalone verifier is also entirely table-free. Its size is not static
lookup overhead: 38,801 of 51,055 bytes derive and bind four complete RNS
vectors to shared 256-bit values, while 10,794 bytes perform the actual
modular-product relations. The reusable `carry::bound::bind_value` boundary is
<!-- metric:prime_rns_bind_value -->9777<!-- /metric:prime_rns_bind_value -->
bytes: <!-- metric:prime_rns_bind_value_validation -->208<!-- /metric:prime_rns_bind_value_validation -->
bytes validate limbs, <!-- metric:prime_rns_bind_value_binding -->9475<!-- /metric:prime_rns_bind_value_binding -->
bytes derive all residues, and <!-- metric:prime_rns_bind_value_routing -->94<!-- /metric:prime_rns_bind_value_routing -->
bytes route the dual output. This plain binder proves only that the shared
integer is below `2^256`. `carry::bound::bind_value_below(N)` is
<!-- metric:prime_rns_bind_value_below -->9864<!-- /metric:prime_rns_bind_value_below -->
bytes and additionally proves the fixed field bound required for `lhs`, `rhs`,
or `r` unless that predicate is established elsewhere. A composed program can
certify persistent values once at their introduction boundary; the 51,055-byte
fused API deliberately rechecks all four values to provide a sound standalone
operation.

`carry::composable` makes that reuse executable in a separate 46-prime basis.
Its 513-bit basis product is 1.01865 times `2^512`. The introduction fragment
`carry::composable::bind_value` consumes 16 centered limbs and 46 binding
carries, proves the value below the secp256k1 modulus, and returns only its 46
canonical residues. It is
<!-- metric:prime_rns_composable_bind_value -->9835<!-- /metric:prime_rns_composable_bind_value -->
bytes: <!-- metric:prime_rns_composable_bind_value_validation -->248<!-- /metric:prime_rns_composable_bind_value_validation -->
bytes of limb/field validation,
<!-- metric:prime_rns_composable_bind_value_binding -->9487<!-- /metric:prime_rns_composable_bind_value_binding -->
bytes of residue binding, and
<!-- metric:prime_rns_composable_bind_value_routing -->100<!-- /metric:prime_rns_composable_bind_value_routing -->
bytes of routing. For `N-1`, its 62 witness items serialize to
<!-- metric:prime_rns_composable_bind_value_witness -->195<!-- /metric:prime_rns_composable_bind_value_witness -->
bytes; it contains
<!-- metric:prime_rns_composable_bind_value_opcodes -->6168<!-- /metric:prime_rns_composable_bind_value_opcodes -->
static non-push opcodes and peaks at
<!-- metric:prime_rns_composable_bind_value_stack -->72<!-- /metric:prime_rns_composable_bind_value_stack -->
combined stack items.

The 31,281-byte multiplication then consumes two certified residue vectors,
binds only the hostile quotient and new remainder, and returns a certified
remainder vector that can feed the next multiplication. Its input, bottom to
top, is `preserved | lhs residues | rhs residues | q limbs | r limbs | hint
groups`; each reverse-coordinate hint group contains a quotient-binding carry,
remainder-binding carry, and relation carry. For `(N-1)^2`, the incremental
170-item witness serializes to 471 bytes and excludes the two live certified
operand vectors. The fragment contains
<!-- metric:prime_rns_composable_hinted_mod_mul_opcodes -->20799<!-- /metric:prime_rns_composable_hinted_mod_mul_opcodes -->
static non-push opcodes. Tests execute a two-multiplication chain, preserve
unrelated main/alt state, reject every carry class at every coordinate, and
exercise the exact 267-item peak and 1,000-item guard.

There is no static table lifecycle to amortize: table push and drop are both
zero for the binder and multiplication. Instead, global certification is the
reusable cost. When `k` binder fragments and `m` multiplication fragments are
already presented with their documented adjacent inputs, their arithmetic
subtotal is `9,835*k + 31,281*m` bytes. This is not a complete all-witness-at-
entry schedule: circuit-specific witness routing, certificate reordering and
fan-out, terminal predicates, and transaction serialization remain excluded.
In particular, multiplication consumes both operand vectors. A straightforward
46-residue certificate duplication costs another 138 bytes before a square,
so repeated squaring is not the unqualified `31,281`-byte recurrence. The exact
31,281-byte claim applies only when two certified vectors and the gate hints
are already adjacent in the required boundary layout.

The boundary is `fragment-with-memory`: it includes complement and hint
coordinate validation, a per-coordinate choice between a reused streamed table
and plain/centered table-free binary Horner multiplication, shortest-choice
fixed products, all 75 product equations, cleanup, and the returned remainder. Operand pushes,
input-operand coordinate checks, the required global 256-bit bindings, and the
terminal predicate are excluded. The hint witness contains the 225 serialized
quotient, remainder, and complement residues for `(N-1)^2`; the two 75-residue
operands are excluded. The generated fragment has
<!-- metric:prime_rns_hinted_mod_mul_opcodes -->17816<!-- /metric:prime_rns_hinted_mod_mul_opcodes -->
static non-push opcodes.

A separately executed two-proof coordinate-lockstep prototype reselected
shared tables for 25 coordinates, but measured 52,048 bytes and a 753-item
peak. Two independent fragments cost 51,554 bytes. Its 1,391 bytes of relayout
and deeper-query overhead exceeded the ideal 897-byte table saving; a third
proof cannot enter because its 1,125 input items already exceed the stack
limit. This dominated batch is recorded as a negative result rather than a
public API.

The smaller `prime::carry::mul_mod_hinted` is a separate, table-free profile.
It uses 42 target-aware prime coordinates whose product remains greater than
`2^512`. Its packed witness interleaves `lhs_i`, `rhs_i`, `q_i`, `r_i`, an
optional complement coordinate, and an exact signed relation carry. Each
channel checks

```text
lhs_i * center(rhs_i) - q_i * center(N_i) - r_i = carry_i * p_i.
```

These exact products fit four-byte Script-number arithmetic, eliminating all
logarithm, exponent, and modular-reduction tables. Fixed products select among
binary, width-2 NAF, and a bounded shortest affine addition chain. A selected
18-coordinate subbasis with product greater than `2^257` checks
`r + complement = N - 1`; the other 24 complement coordinates are omitted.
Its `fragment-only` metric includes hint-coordinate checks, all 42 exact
relations, cleanup, and the returned 42-residue remainder. The 144-item hint
witness for `(N-1)^2` contains 42 quotient residues, 42 remainder residues, 42
carries, and 18 complement residues; operands, global bindings, and the
terminal predicate are excluded. The generated fragment has
<!-- metric:prime_rns_carry_hinted_mod_mul_opcodes -->8137<!-- /metric:prime_rns_carry_hinted_mod_mul_opcodes -->
static non-push opcodes.

Soundness has an essential non-coordinatewise precondition: `lhs`, `rhs`,
`quotient`, `remainder`, and `remainder_complement` must each already be bound
to an unsigned integer below `2^256`, and the operands must be below `N`.
Under those bounds, `r + complement = N - 1` proves `r < N`; both sides of
`a*b = q*N + r` are below `2^512`, while each product basis used here has
dynamic range greater than `2^512`. The RNS congruences therefore imply exact
integer equality.
`verify_canonical` checks only individual coordinate ranges and is not a
substitute for the global 256-bit binding. Without that binding, arbitrary
RNS hints can satisfy the congruences after wraparound.

The carry profile deliberately does not range-check operand coordinates. Each
operand coordinate must be tied to the claimed globally bounded integer, not
merely accompanied by an unrelated range claim. Carries need no independent
range check: a wrong small carry fails equality, while an oversized Script
integer or intermediate fails numeric decoding. Callers that require a unique
byte encoding must enforce minimal witness-number encoding; the fragment
returns the validated numeric remainder but does not normalize its raw bytes.

`prime::carry::bound::mul_mod_hinted` closes that precondition in the fragment
itself. Its witness supplies four values as 16 centered base-`2^16` limbs plus
four residue-binding carries and one multiplication carry for each of 47
primes. For coordinate `i`, the script derives a canonical residue from the
same limb vector with an exact dot-product equation

```text
offset_i + sum_j(center(2^(16j) mod p_i) * limb_j)
    - residue_i = binding_carry_i * p_i.
```

It validates all limb ranges, proves `lhs`, `rhs`, and `r` are below `N`, and
therefore needs no remainder-complement vector. The 47-prime product has 513
bits, so the bound product congruence cannot wrap. The complete witness has 64
limbs, 188 binding carries, and 47 relation carries. The fragment returns the
16 centered remainder limbs beneath its 47 canonical residues. Shared joint
NAF doubling chains and common-factor extraction make the exact binding dots
substantially smaller. The two widest target-aware coordinates center both
product operands; generation rejects other targets whose exact relation
prefixes would exceed ScriptNum. It has
<!-- metric:prime_rns_bound_carry_hinted_mod_mul_opcodes -->32772<!-- /metric:prime_rns_bound_carry_hinted_mod_mul_opcodes -->
static non-push opcodes; this marker is refreshed from the generated script.

### Range validation

Witness residues are hostile. `add`, `sub`, and especially `mul` assume their
documented encodings; an out-of-range `OP_PICK` index can address unrelated
state or fail. `verify_canonical` preserves one value while checking all 75
coordinates and costs
<!-- metric:prime_rns_verify -->621<!-- /metric:prime_rns_verify --> bytes with a
<!-- metric:prime_rns_verify_stack -->78<!-- /metric:prime_rns_verify_stack -->-item
peak when the value is already on the stack. The residue encoding of
`2^256-1` serializes to
<!-- metric:prime_rns_verify_witness -->167<!-- /metric:prime_rns_verify_witness -->
witness bytes; the worst canonical vector uses
<!-- metric:prime_rns_verify_witness_max -->196<!-- /metric:prime_rns_verify_witness_max -->.
`verify_centered` checks the mixed centered encoding. Validation is deliberately
separate so a commitment or conversion boundary can validate once and reuse
the result. Coordinate range checks alone do not prove that the CRT
representative is below `2^256`; the boundary that introduces each operand must
also bind that global 256-bit range for the no-wrap product claim.

## Efficiency of larger primes

A prime contributes only `log2(p)` range bits, while its dense lookup memory
grows linearly in `p`. Larger primes reduce the number of residue coordinates
but are less efficient in locking-script bytes. An inspected stack-only search
can use about 54 large primes in the 587–941 range, but their table-item total
is more than three times this profile's. The chosen small-prime basis instead
uses more witness elements and a much smaller streamed script. The omission of
47 is the result of the whole-basis byte optimization, not a number-theoretic
requirement.

## Security and deployment

No cryptographic security parameter is claimed. The encoding is not a
commitment, and the combined modulus is a ring with zero divisors rather than a
field. Equality and multiplication by a unit's coordinatewise modular inverse
are local. Ordering, sign, ordinary integer quotient, and reduction to another
256-bit modulus require a CRT/mixed-radix boundary or a separately verified
range witness; a non-unit has no inverse modulo `M`.

The multiplication fragment is far above the legacy/P2WSH 10,000-byte script
and 201-non-push-opcode limits. It is evaluated only in tapscript context,
where BIP342 removes those two limits, but no Bitcoin Core consensus or relay
policy matrix has been run. Results are `locally-reproduced`; deployment is
`unclassified`. The metric helper disables stack-limit enforcement while
recording peaks, while unit tests separately exercise the same paths with the
strict stack limit enabled. The refreshed 75-prime multiply peaks at 183 items;
the measured secp256k1 no-carry reduction peaks at 384 items, and its
target-independent generation guard reserves a conservative 466. The packed
carry profile is exercised at its exact 231-item peak and at exactly 1,000
items after unrelated state is added. The standalone bound profile is likewise
strict-executed at its exact 305-item peak and with exactly 1,000 items. The
conditional fragments still need their documented external bindings; the
standalone profile closes that obligation locally. The composable profile
closes q/r locally but accepts lhs/rhs certificates by verified control-flow
provenance: they must come from its global field-value binder or a prior gate,
not from raw witness residues or independent coordinate checks. Its binder and
gate are strict-executed at exact 72- and 267-item peaks and with their
generation guards filled to 1,000 items. Every fragment still needs a terminal
predicate, clean-stack composition, and transaction-weight accounting.

See the repository's [script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) notes for the comparison rules.

## Witness, hints, and stack contract

Basic RNS add/subtract/multiply needs no hints. Original-RNS residues remain
ordered with modulus 4 on top and modulus 11 deepest. Prime-RNS residues have
modulus 2 on top and modulus 383 deepest. `mul(preserved_items)` starts from
`preserved | lhs | rhs`, consumes both operands, streams each table internally,
or uses its table-free coordinate candidate, and then leaves the result on the
altstack. `preserved_items` must count unrelated live items across both stacks
for the generation-time 1,000-item guard.

`prime::batch::mul(products, preserved_items)` instead expects, from the top,
all operand pairs for modulus 2, then all pairs for modulus 3, and so on. It
leaves results on the altstack in the same processing order. `products` is
limited to six; callers must preserve the coordinate-major layout across
adjacent operations or account separately for transposition.

`mul_mod_hinted(target, preserved_items)` starts from
`preserved | lhs | rhs | quotient | remainder | remainder_complement`, consumes
all vectors except the remainder, and returns that remainder on the main stack.
The three hint vectors are mandatory, public, and derived from the operands and
fixed target. Their global 256-bit bindings are caller obligations, not implied
by the local coordinate checks.

`prime::carry::mul_mod_hinted(target, preserved_items)` instead consumes the
packed 42-coordinate groups produced by `prime::carry::push_hinted_witness`.
Only the 18 complement-subbasis groups contain a complement coordinate. It
returns a 42-residue carry-basis value, which is a distinct representation
from the contiguous 75-residue value above.

`prime::carry::bound::mul_mod_hinted(target, preserved_items)` is the
self-contained alternative. It consumes the layout produced by
`prime::carry::bound::push_hinted_witness`, proves all global bindings and
field bounds locally, and returns both a centered 16-limb remainder and its
47-residue encoding. `prime::carry::bound::bind_value` separately certifies
one reusable limb-plus-residue value below `2^256` for larger composed scripts;
`bind_value_below` also proves a fixed field bound.

`prime::carry::composable::bind_value(preserved_items)` consumes
`preserved | centered_limbs[16] | binding_carries[46]` and returns only
`preserved | certified_residues[46]`, with coordinate zero on top. It validates
the secp256k1 field bound as well as the global limb-to-residue binding.
`prime::carry::composable::mul_mod_hinted(preserved_items)` then consumes,
bottom to top, `preserved | lhs[46] | rhs[46] | q_limbs[16] | r_limbs[16] |
hints`. Hints are 46 reverse-coordinate groups of `q_binding | r_binding |
relation`. It consumes both operand certificates and every hint, returning
only a certified `r[46]` vector in the same coordinate-zero-on-top order.
`preserved_items` counts unrelated items across both stacks.

That contract describes an operation boundary, not an all-witness-at-entry
circuit layout. The measured 471-byte witness covers only one gate's 170
incremental items and excludes its live certificates. Scheduling several
initial witness groups, moving certificates between gates, and duplicating a
certificate for fan-out or squaring require explicit extra script. The
two-gate unit test inserts later inputs as script constants, so it validates
certificate-state composition without claiming a complete witness router.

## Knowledge-base integration

See the pages for the [original RNS](../../../knowledge/primitives/rns.md) and
[prime-log RNS](../../../knowledge/primitives/prime-rns.md), the
[arithmetic](../../../knowledge/comparisons/arithmetic.md) and
[lookup](../../../knowledge/comparisons/lookup-strategies.md) comparisons,
[negative results](../../../knowledge/negative-results/index.md), and
[open problems](../../../knowledge/open-problems.md).
