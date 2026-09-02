# secp256k1 certified RNS backend

This backend represents one secp256k1 field value with 46 canonical prime
residues. It builds on generic helpers in
[`../../../arithmetic/rns`](../../../arithmetic/rns/) but owns the fixed field
modulus, basis, certificate boundary, and field-specific multiplication gate.

`bind_value` consumes 16 centered base-`2^16` limbs and 46 binding carries,
proves the value is below the secp256k1 modulus, and returns 46 certified
residues. `mul_mod_hinted` consumes two such certificates, binds hostile
quotient and remainder limbs locally, verifies the exact modular relations,
and returns a reusable remainder certificate.

## Metrics

Fragments exclude operand pushes, terminal predicates, certificate fan-out,
and transaction serialization. The multiplication witness is incremental: its
two live operand certificates are excluded.

| Fragment | Locking script | Witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Introduce one certified value | <!-- metric:prime_rns_composable_bind_value -->9832<!-- /metric:prime_rns_composable_bind_value --> bytes | <!-- metric:prime_rns_composable_bind_value_witness -->195<!-- /metric:prime_rns_composable_bind_value_witness --> bytes | <!-- metric:prime_rns_composable_bind_value_stack -->72<!-- /metric:prime_rns_composable_bind_value_stack --> |
| Multiply two certified values | <!-- metric:prime_rns_composable_hinted_mod_mul -->31257<!-- /metric:prime_rns_composable_hinted_mod_mul --> bytes | <!-- metric:prime_rns_composable_hinted_mod_mul_witness -->471<!-- /metric:prime_rns_composable_hinted_mod_mul_witness --> bytes | <!-- metric:prime_rns_composable_hinted_mod_mul_stack -->267<!-- /metric:prime_rns_composable_hinted_mod_mul_stack --> |

Binder attribution: validation
<!-- metric:prime_rns_composable_bind_value_validation -->247<!-- /metric:prime_rns_composable_bind_value_validation -->
bytes, residue binding
<!-- metric:prime_rns_composable_bind_value_binding -->9485<!-- /metric:prime_rns_composable_bind_value_binding -->
bytes, and routing
<!-- metric:prime_rns_composable_bind_value_routing -->100<!-- /metric:prime_rns_composable_bind_value_routing -->
bytes. It contains
<!-- metric:prime_rns_composable_bind_value_opcodes -->6168<!-- /metric:prime_rns_composable_bind_value_opcodes -->
static non-push opcodes.

Multiplication attribution: table push
<!-- metric:prime_rns_composable_hinted_mod_mul_table_push -->0<!-- /metric:prime_rns_composable_hinted_mod_mul_table_push -->,
table drop
<!-- metric:prime_rns_composable_hinted_mod_mul_table_drop -->0<!-- /metric:prime_rns_composable_hinted_mod_mul_table_drop -->,
validation
<!-- metric:prime_rns_composable_hinted_mod_mul_validation -->427<!-- /metric:prime_rns_composable_hinted_mod_mul_validation -->,
quotient binding
<!-- metric:prime_rns_composable_hinted_mod_mul_quotient_binding -->9851<!-- /metric:prime_rns_composable_hinted_mod_mul_quotient_binding -->,
remainder binding
<!-- metric:prime_rns_composable_hinted_mod_mul_remainder_binding -->9663<!-- /metric:prime_rns_composable_hinted_mod_mul_remainder_binding -->,
modular relations
<!-- metric:prime_rns_composable_hinted_mod_mul_modular_relation -->10794<!-- /metric:prime_rns_composable_hinted_mod_mul_modular_relation -->,
and routing
<!-- metric:prime_rns_composable_hinted_mod_mul_routing_output -->522<!-- /metric:prime_rns_composable_hinted_mod_mul_routing_output -->
bytes. It contains
<!-- metric:prime_rns_composable_hinted_mod_mul_opcodes -->20778<!-- /metric:prime_rns_composable_hinted_mod_mul_opcodes -->
static non-push opcodes.

## Witness and validity contract

Binder input is `preserved | centered_limbs[16] | binding_carries[46]`.
Multiplication input is `preserved | lhs[46] | rhs[46] | q_limbs[16] |
r_limbs[16] | hints`, where each reverse-coordinate hint group is
`q_binding | r_binding | relation`. Coordinate zero is nearest the top. The
gate consumes both operand certificates and all hints, returning only `r[46]`.

Raw residue vectors are not certificates. Both operands must originate from
this binder, an earlier multiplication on the same verified path, or an
equivalent global proof. Duplicating a certificate for fan-out or squaring
costs extra script and stack; the 31,257-byte figure assumes the two required
certificates are already adjacent. Tests corrupt every carry class, exercise a
two-gate chain, preserve unrelated state, and enforce the 1,000-item generator
guard. Evidence is `locally-reproduced`; deployment is `unclassified`.
