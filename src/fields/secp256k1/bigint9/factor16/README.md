# secp256k1 bigint9 factor-16 profile

This profile stores a logical field value as `E(x) = x/16 mod p`. It reuses the
ordinary bigint9 normalized-Karatsuba product core, folds `16*a*b` to degree
28, and proves the folded relation with one signed residual and 28 carries.
Its output is `E(x*y)`, not an ordinary-domain product.

`encode` and `decode` are host helpers. Any in-Script conversion, mixed-profile
routing, resident table, batching, fan-out, terminal predicate, or transaction
serialization is outside the measured fragments.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Multiply two certified encoded operands | <!-- metric:secp256k1_field_factor16_mul -->20447<!-- /metric:secp256k1_field_factor16_mul --> bytes | <!-- metric:secp256k1_field_factor16_hint_witness -->37<!-- /metric:secp256k1_field_factor16_hint_witness --> bytes / <!-- metric:secp256k1_field_factor16_hint_items -->29<!-- /metric:secp256k1_field_factor16_hint_items --> incremental hint items | <!-- metric:secp256k1_field_factor16_stack -->719<!-- /metric:secp256k1_field_factor16_stack --> |
| Multiply from two raw encoded operands | <!-- metric:secp256k1_field_factor16_standalone -->21719<!-- /metric:secp256k1_field_factor16_standalone --> bytes | <!-- metric:secp256k1_field_factor16_standalone_witness -->103<!-- /metric:secp256k1_field_factor16_standalone_witness --> bytes / 87 complete data items | <!-- metric:secp256k1_field_factor16_standalone_stack -->719<!-- /metric:secp256k1_field_factor16_standalone_stack --> |

| Component | Bytes |
| --- | ---: |
| Push 513-entry table | <!-- metric:secp256k1_field_factor16_table_setup -->1536<!-- /metric:secp256k1_field_factor16_table_setup --> |
| Drop table | <!-- metric:secp256k1_field_factor16_table_drop -->257<!-- /metric:secp256k1_field_factor16_table_drop --> |
| Normalized-Karatsuba product generation | <!-- metric:secp256k1_field_factor16_product_generation -->15597<!-- /metric:secp256k1_field_factor16_product_generation --> |
| Folded exact relation and derived digits | <!-- metric:secp256k1_field_factor16_relation -->2642<!-- /metric:secp256k1_field_factor16_relation --> |
| Input/temporary cleanup and output certification | <!-- metric:secp256k1_field_factor16_cleanup -->415<!-- /metric:secp256k1_field_factor16_cleanup --> |
| **Total** | **20,447** |

The non-table computation is
<!-- metric:secp256k1_field_factor16_computation -->18654<!-- /metric:secp256k1_field_factor16_computation -->
bytes and contains
<!-- metric:secp256k1_field_factor16_opcodes -->13089<!-- /metric:secp256k1_field_factor16_opcodes -->
static non-push opcodes. Compared with the ordinary one-shot profile, the
locking script is 53 bytes smaller; the material differences are 29
rather than 67 hints and 38 fewer peak stack items.

Inputs are `preserved | lhs[28..0] | rhs[28..0] | t | c[27..0]`; output is a
certified factor-16 encoding `r[28..0]`. One residual and 28 carries prove
`G - t*p = r`, where `G` evaluates to `16*lhs*rhs`. Script derives and certifies
the remainder. Hints are hostile, and operands must already be certified or
enter through the raw wrapper.

The savings apply only while every consumer preserves the factor-16 semantic
domain. The ordinary multiplication, square, and preloaded batches do not.
Local strict tapscript tests enforce the 1,000-item limit; evidence is
`locally-reproduced` and deployment remains `unclassified`.
