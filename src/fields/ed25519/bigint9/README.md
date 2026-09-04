# Ed25519 bigint9 factor-8 field multiplication

This backend verifies exact multiplication in `GF(2^255-19)` with 29 balanced
radix-512 digits. Values are stored as `E(x)=x/8 mod p`, so encoded operands
`a=E(x)` and `b=E(y)` produce `8ab=E(xy)`. A 646-query normalized-Karatsuba
product is folded by `8*512^28 = p+19`; one residual and 28 witnessed carries
then prove an exact integer relation. Script derives and certifies the returned
remainder. Raw witness operands are hostile unless the standalone wrapper
certifies them.

## Parameters

- `p=2^255-19`, radix 512, 29 digits, and the 14/15 Karatsuba split are fixed.
- Lower digits are in `[-256,256)`; the top digit and exact tail are checked so
  the represented integer is in `[0,p)`.
- `preserved_items` has no default. It is the exact unrelated combined-stack
  state and must not exceed 281 items for this gate.
- The factor-8 representation is mandatory throughout a composed field circuit.

## Script metrics

Both rows are `fragment-with-memory`: they include the 513-entry quarter-square
table setup/drop, product generation, exact folded relation, input/hint cleanup,
and returned 29-digit result. They exclude witness pushes, a terminal predicate,
tapleaf/control-block serialization, and transaction context. The certified row
also excludes operand certification. Witness sizes use encoded logical
`(p-1)^2`; they are representative, not maxima.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Two certified factor-8 operands | <!-- metric:ed25519_bigint9_mul -->19903<!-- /metric:ed25519_bigint9_mul --> bytes | <!-- metric:ed25519_bigint9_mul_hint_witness -->31<!-- /metric:ed25519_bigint9_mul_hint_witness --> bytes / <!-- metric:ed25519_bigint9_mul_hint_items -->29<!-- /metric:ed25519_bigint9_mul_hint_items --> incremental items | <!-- metric:ed25519_bigint9_mul_stack -->719<!-- /metric:ed25519_bigint9_mul_stack --> |
| Two raw factor-8 operand encodings | <!-- metric:ed25519_bigint9_mul_standalone -->21145<!-- /metric:ed25519_bigint9_mul_standalone --> bytes | <!-- metric:ed25519_bigint9_mul_standalone_witness -->93<!-- /metric:ed25519_bigint9_mul_standalone_witness --> bytes / 87 complete data items | <!-- metric:ed25519_bigint9_mul_standalone_stack -->719<!-- /metric:ed25519_bigint9_mul_standalone_stack --> |

The certified gate breaks down as follows:

| Component | Bytes |
| --- | ---: |
| Quarter-square table setup | <!-- metric:ed25519_bigint9_mul_table_setup -->1536<!-- /metric:ed25519_bigint9_mul_table_setup --> |
| Quarter-square table drop | <!-- metric:ed25519_bigint9_mul_table_drop -->257<!-- /metric:ed25519_bigint9_mul_table_drop --> |
| Normalized-Karatsuba product generation | <!-- metric:ed25519_bigint9_mul_product_generation -->15597<!-- /metric:ed25519_bigint9_mul_product_generation --> |
| Factor-8 pseudo-Mersenne relation | <!-- metric:ed25519_bigint9_mul_relation -->2113<!-- /metric:ed25519_bigint9_mul_relation --> |
| Cleanup and canonical output check | <!-- metric:ed25519_bigint9_mul_cleanup -->400<!-- /metric:ed25519_bigint9_mul_cleanup --> |
| Computation excluding table lifecycle | <!-- metric:ed25519_bigint9_mul_computation -->18110<!-- /metric:ed25519_bigint9_mul_computation --> |
| Static non-push opcodes | <!-- metric:ed25519_bigint9_mul_opcodes -->12593<!-- /metric:ed25519_bigint9_mul_opcodes --> |

## Security

The verifier checks one exact integer identity, not an RNS congruence. Every
carry and the residual is bound by that identity; Script derives the output and
proves it canonical, so there is exactly one accepted field result. Honest
residuals are in `[-5558,5557]`, carries have absolute value at most 98,834,
and the largest conservative pre-carry bound is 50,602,882, below the positive
ScriptNum limit. Oversized hostile hints fail closed when used by arithmetic.

This is an experimental arithmetic primitive, not an EdDSA verifier. An EdDSA
construction must additionally enforce canonical scalar and point encodings,
curve membership, non-small-order/subgroup requirements appropriate to the
chosen verification equation, challenge hashing, and public-key binding.

## Script compatibility and standardness

The fragment uses ordinary stack and arithmetic opcodes but is intended for
tapscript. Its locking script is too large for P2SH, P2WSH, and legacy's
10,000-byte consensus limit. Tapscript removes the script-size and opcode-count
limits, but a complete transaction and Bitcoin Core consensus/policy validation
have not been measured. See [`docs/script-types.md`](../../../../docs/script-types.md)
and [`docs/standardness.md`](../../../../docs/standardness.md).

## Witness and hints

The main stack is `lhs[28..0] | rhs[28..0] | t | carry[27..0]`, with carry zero
nearest the top. Each item is a minimally encoded ScriptNum. The 29 hint items
are public prover assistance, mandatory, and individually bound by the exact
carry chain. Operand certification must have happened earlier on the same
verified path unless `mul_mod_hinted_from_raw_witness` is used.

## Stack contract

`mul_mod_hinted` consumes both certified operands and all hints, uses the
altstack for product coefficients and derived output digits, and returns
`r[28] ... r[0]` with digit zero nearest the top. The measured combined-stack
peak is enforced by the generator; at most 281 unrelated items may coexist.

## Operational notes

All generated scripts compile through `compile_with_policy()`. The current
script is below the 32 KiB optimizer cutoff. Deterministic tests cover the
algebraic fold, boundaries and seeded values, factor-8 closure, analytic
ScriptNum bounds, every tampered hint, malformed operand digits, and the stack
guard. Execution uses `bitcoin-scriptexec` in tapscript context with the
1,000-item stack limit enabled, so the evidence level is `locally-reproduced`
and the deployment class remains `unclassified`.

This bigint9 construction is retained as the exact normalized-Karatsuba
baseline. The field family now also contains operand-specific radix-16 and
radix-32 table backends that bind every selected product to a certified input
digit and verify the complete carry relation. The original 2–3 KB estimate
still omitted the shifted-product/carry work needed for that binding; see
NR-030 in the negative-results index and the field-family README for the
measured optimized backend.

The dedicated release benchmark (`cargo run --locked --release --example
ed25519_field_benchmark`) measured 100 strict executions on the local host:
0.272 ms median, 0.323 ms p95, and 0.573 ms maximum. Policy compilation took
0.855 s. These wall times are diagnostic and machine-dependent.

## Knowledge-base integration

See the [primitive page](../../../../knowledge/primitives/ed25519-field.md),
[arithmetic comparison](../../../../knowledge/comparisons/arithmetic.md),
[lookup-table technique](../../../../knowledge/techniques/lookup-tables.md),
[witness-hint technique](../../../../knowledge/techniques/witness-hints.md), and
OP-018 in [open problems](../../../../knowledge/open-problems.md).
