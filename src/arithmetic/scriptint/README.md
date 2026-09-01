# ScriptNum arithmetic

This module contains arithmetic over Bitcoin's four-byte Script integers. It
implements multiplication by a compile-time constant and Euclidean division
by a positive compile-time constant. Division uses a witness-supplied quotient
hint and derives the remainder without relying on disabled `OP_DIV`, `OP_MOD`,
or `OP_MUL` opcodes.

## Parameters

- `mul_by_constant(multiplier)` accepts any `u32` compile-time multiplier,
  including zero. The input, result, and intermediate double-and-add values
  must fit the Script-number domain. There is no default.
- `divisor`: required positive compile-time constant in
  `1..=2,147,483,647`; there is no default.
- `hinted_div_rem` returns quotient and remainder.
- `hinted_div` returns only the quotient.
- `hinted_rem` returns only the remainder.
- `dividend` and `quotient_hint` are minimally encoded, at-most-four-byte
  Script integers supplied on the stack. Their product and every intermediate
  arithmetic value must also fit the four-byte Script-number domain.

## Script metrics

Sizes are generated locking fragments. Witness sizes use Bitcoin's serialized
witness encoding. Maximum stack items count the combined main and alt stacks.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `mul_by_constant(13)` | <!-- metric:scriptint_mul_constant_13 -->10<!-- /metric:scriptint_mul_constant_13 --> bytes | <!-- metric:scriptint_mul_witness_min -->2<!-- /metric:scriptint_mul_witness_min -->–<!-- metric:scriptint_mul_witness_max -->6<!-- /metric:scriptint_mul_witness_max --> bytes (one operand) | <!-- metric:scriptint_mul_stack -->4<!-- /metric:scriptint_mul_stack --> |
| `hinted_div_rem(8)` | <!-- metric:scriptint_div_rem_8 -->13<!-- /metric:scriptint_div_rem_8 --> bytes | <!-- metric:scriptint_div_witness_min -->3<!-- /metric:scriptint_div_witness_min -->–<!-- metric:scriptint_div_witness_max -->11<!-- /metric:scriptint_div_witness_max --> bytes | <!-- metric:scriptint_div_rem_stack -->5<!-- /metric:scriptint_div_rem_stack --> |
| `hinted_div(8)` | <!-- metric:scriptint_div_8 -->14<!-- /metric:scriptint_div_8 --> bytes | same | same or lower |
| `hinted_rem(8)` | <!-- metric:scriptint_rem_8 -->14<!-- /metric:scriptint_rem_8 --> bytes | same | same or lower |

## Security

There is no cryptographic security parameter. Constant multiplication is a
deterministic arithmetic fragment. Division soundness follows from checking

`dividend = quotient_hint * divisor + remainder`

and `0 <= remainder < divisor`. Together these conditions uniquely determine
the Euclidean quotient and remainder, provided all Script-number operations
execute without overflow.

## Script compatibility and standardness

The fragments use opcodes available in bare script, P2SH, P2WSH, and tapscript.
They are small and do not independently violate opcode-count or script-size
limits. Bare outputs are generally non-standard, and the complete script must
still satisfy minimal-number encoding, cleanstack, size, and transaction policy
rules. See [`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

The fragments return arithmetic values rather than a terminal boolean, so the
caller must consume their result in a predicate. They do not by themselves
claim cleanstack compliance.

## Witness and hints

Constant multiplication needs no hint; its operand may come from the witness or
an earlier fragment. The quotient hint is mandatory for division. Immediately
before a division fragment, the quotient must be below the dividend:

`... quotient_hint dividend`

For a witness-only input this means serializing the quotient first and the
dividend second. The divisor is embedded in the locking script and the
remainder is derived; neither requires a witness item.

## Stack contract and operational notes

- `hinted_div_rem`: `... q x -> ... q r` (`r` is on top).
- `hinted_div`: `... q x -> ... q`.
- `hinted_rem`: `... q x -> ... r`.
- `mul_by_constant`: `... x -> ... multiplier*x`.
- Negative dividends use Euclidean division with a non-negative remainder.
- Values outside Bitcoin's signed-magnitude four-byte Script-number domain are
  unsupported. A mathematically valid operation can therefore still fail if
  `q * divisor` or another intermediate value overflows that domain.

The design is independently implemented from the hint-verification technique
described in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/blob/master/composite-opcodes.md#op_mod-and-op_div).
