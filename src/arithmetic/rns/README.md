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
| Canonical | Multiply | <!-- metric:prime_rns_mul -->37471<!-- /metric:prime_rns_mul --> bytes | <!-- metric:prime_rns_mul_stack -->462<!-- /metric:prime_rns_mul_stack --> |

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

`mul` streams one coordinate at a time, so tables never coexist:

1. Modulo 2 uses `OP_BOOLAND` and modulo 3 uses a table-free equality formula.
2. Primes 5 through 19 use full canonical discrete-log/exponent tables because
   their shorter query outweighs a tiny table-size increase.
3. Primes 23 through 151 use signed magnitude logs and canonical half-exponent
   entries.
4. Primes 157 through 383 use the same query with centered half-exponent
   entries, then normalize the result back to canonical form. The smaller
   table literals save more bytes than the five-byte normalization tail costs.

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
<!-- metric:prime_rns_mul_opcodes -->10787<!-- /metric:prime_rns_mul_opcodes -->
static non-push opcodes. A resident-table variant is intentionally omitted: its
combined table footprint exceeds Bitcoin Script's 1,000-item stack limit.

### Witness-hinted modular reduction

`mul_mod_hinted` verifies `a*b = q*N + r` for a positive, generation-time
modulus `N` of at most 256 bits. It consumes five canonical RNS vectors in the
order `lhs | rhs | quotient | remainder | remainder_complement`, where the
complement is `N - 1 - r`, and returns the remainder vector. Quotient,
remainder, and complement are public derived hints.

The measured secp256k1-field instance uses
`N = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`:

| Fragment | Locking script | Hint witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Hinted modular multiply | <!-- metric:prime_rns_hinted_mod_mul -->69199<!-- /metric:prime_rns_hinted_mod_mul --> bytes | <!-- metric:prime_rns_hinted_mod_mul_witness -->477<!-- /metric:prime_rns_hinted_mod_mul_witness --> bytes | <!-- metric:prime_rns_hinted_mod_mul_stack -->612<!-- /metric:prime_rns_hinted_mod_mul_stack --> |

The boundary is `fragment-with-memory`: it includes complement and hint
coordinate validation, streamed variable-product tables, streamed
constant-product tables selected per coordinate, all 75 product equations,
cleanup, and the returned remainder. Operand pushes, input-operand coordinate
checks, the required global 256-bit bindings, and the terminal predicate are
excluded. The hint witness contains the 225 serialized quotient, remainder,
and complement residues for `(N-1)^2`; the two 75-residue operands are
excluded. The generated fragment has
<!-- metric:prime_rns_hinted_mod_mul_opcodes -->23990<!-- /metric:prime_rns_hinted_mod_mul_opcodes -->
static non-push opcodes.

Soundness has an essential non-coordinatewise precondition: `lhs`, `rhs`,
`quotient`, `remainder`, and `remainder_complement` must each already be bound
to an unsigned integer below `2^256`, and the operands must be below `N`.
Under those bounds, `r + complement = N - 1` proves `r < N`; both sides of
`a*b = q*N + r` are below `2^512`, while the 75-prime dynamic range is larger
than `2^512`. The RNS congruences therefore imply exact integer equality.
`verify_canonical` checks only individual coordinate ranges and is not a
substitute for the global 256-bit binding. Without that binding, arbitrary
RNS hints can satisfy the congruences after wraparound.

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
recording peaks, while unit tests separately execute the 462-item path under
the strict stack limit; the hinted-reduction path is likewise exercised at its
612-item peak. The fragment still needs input validation, a terminal
predicate, clean-stack composition, and transaction-weight accounting.
See the repository's [script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) notes for the comparison rules.

## Witness, hints, and stack contract

Basic RNS add/subtract/multiply needs no hints. Original-RNS residues remain
ordered with modulus 4 on top and modulus 11 deepest. Prime-RNS residues have
modulus 2 on top and modulus 383 deepest. `mul(preserved_items)` starts from
`preserved | lhs | rhs`, consumes both operands, streams each table internally,
and leaves the result on the altstack. `preserved_items` must count unrelated
live items across both stacks for the generation-time 1,000-item guard.

`mul_mod_hinted(target, preserved_items)` starts from
`preserved | lhs | rhs | quotient | remainder | remainder_complement`, consumes
all vectors except the remainder, and returns that remainder on the main stack.
The three hint vectors are mandatory, public, and derived from the operands and
fixed target. Their global 256-bit bindings are caller obligations, not implied
by the local coordinate checks.

## Knowledge-base integration

See the pages for the [original RNS](../../../knowledge/primitives/rns.md) and
[prime-log RNS](../../../knowledge/primitives/prime-rns.md), the
[arithmetic](../../../knowledge/comparisons/arithmetic.md) and
[lookup](../../../knowledge/comparisons/lookup-strategies.md) comparisons,
[negative results](../../../knowledge/negative-results/index.md), and
[open problems](../../../knowledge/open-problems.md).
