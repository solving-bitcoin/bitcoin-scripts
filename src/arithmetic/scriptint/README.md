# ScriptNum arithmetic

This module contains arithmetic over Bitcoin's four-byte Script integers. It
implements multiplication by a compile-time constant and Euclidean division
by a positive compile-time constant. The hinted API checks a supplied quotient;
`bounded::div_rem` computes it without hints for a canonical nonnegative bounded
dividend. Neither uses disabled `OP_DIV`, `OP_MOD`, or `OP_MUL` opcodes.

## Parameters

- `mul_by_constant(multiplier)` accepts any `u32` compile-time multiplier,
  including zero. The input, result, and intermediate double-and-add values
  must fit the Script-number domain. There is no default.
- `divisor`: required positive compile-time constant in
  `1..=2,147,483,647`; there is no default.
- `hinted_div_rem` returns quotient and remainder.
- `hinted_div` returns only the quotient.
- `hinted_rem` returns only the remainder.
- `bounded::div_rem(divisor, maximum)` accepts one canonical dividend in
  `0..=maximum`, with required `maximum` in `0..=2,147,483,647`, and returns
  canonical quotient and remainder with no hints. Negative dividends remain
  supported only by the separate hinted API.
- `verify_canonical` preserves one minimally encoded at-most-four-byte
  ScriptNum and rejects aliases, negative zero, and oversized items.
- For hinted division, `dividend` and `quotient_hint` are minimally encoded, at-most-four-byte
  Script integers supplied on the stack. Their product and every intermediate
  arithmetic value must also fit the four-byte Script-number domain.

Minimal ScriptNum serialization crosses byte boundaries at `127/128`,
`255/256`, and `-128/-129`; positive values whose high data bit is set gain a
sign-preserving byte. These encoding changes do not alter the Euclidean
division contract. The test suite exercises each boundary explicitly.

## Script metrics

Sizes are generated locking fragments. Witness sizes use Bitcoin's serialized
witness encoding. Maximum stack items count the combined main and alt stacks.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `mul_by_constant(13)` | <!-- metric:scriptint_mul_constant_13 -->10<!-- /metric:scriptint_mul_constant_13 --> bytes | <!-- metric:scriptint_mul_witness_min -->2<!-- /metric:scriptint_mul_witness_min -->–<!-- metric:scriptint_mul_witness_max -->6<!-- /metric:scriptint_mul_witness_max --> bytes (one operand) | <!-- metric:scriptint_mul_stack -->4<!-- /metric:scriptint_mul_stack --> |
| `hinted_div_rem(8)` | <!-- metric:scriptint_div_rem_8 -->13<!-- /metric:scriptint_div_rem_8 --> bytes | <!-- metric:scriptint_div_witness_min -->3<!-- /metric:scriptint_div_witness_min -->–<!-- metric:scriptint_div_witness_max -->11<!-- /metric:scriptint_div_witness_max --> bytes | <!-- metric:scriptint_div_rem_stack -->5<!-- /metric:scriptint_div_rem_stack --> |
| `hinted_div(8)` | <!-- metric:scriptint_div_8 -->14<!-- /metric:scriptint_div_8 --> bytes | same | same or lower |
| `hinted_rem(8)` | <!-- metric:scriptint_rem_8 -->14<!-- /metric:scriptint_rem_8 --> bytes | same | same or lower |
| `verify_canonical()` | <!-- metric:scriptint_verify_canonical -->5<!-- /metric:scriptint_verify_canonical --> bytes | <!-- metric:scriptint_verify_canonical_witness -->6<!-- /metric:scriptint_verify_canonical_witness --> bytes (one 4-byte item) | <!-- metric:scriptint_verify_canonical_stack -->4<!-- /metric:scriptint_verify_canonical_stack --> |

## Security

There is no cryptographic security parameter. Constant multiplication is a
deterministic arithmetic fragment. Hinted division soundness follows from checking

`dividend = quotient_hint * divisor + remainder`

and `0 <= remainder < divisor`. Together these conditions uniquely determine
the Euclidean quotient and remainder, provided all Script-number operations
execute without overflow.

## Script compatibility and standardness

The fragments use opcodes available in bare script, P2SH, P2WSH, and tapscript.
The original constant-multiplication and hinted-division fragments fit the
individual opcode-count and script-size bounds. Bounded-division configurations
can exceed them; see the measured full-range case below. Bare outputs are
generally non-standard, and a complete script must still satisfy its encoding,
cleanstack, size, and transaction policy rules. See [`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

The fragments return arithmetic values rather than a terminal boolean, so the
caller must consume their result in a predicate. They do not by themselves
claim cleanstack compliance.

## Witness and hints

Constant multiplication needs no hint; its operand may come from the witness or
an earlier fragment. The quotient hint is mandatory for `hinted_*` division;
`bounded::div_rem` needs none. Before a `hinted_*` fragment, the quotient hint
must be below the dividend:

`... quotient_hint dividend`

For a witness-only input this means serializing the quotient first and the
dividend second. The divisor is embedded in the locking script and the
remainder is derived; neither requires a witness item.

## Stack contract and operational notes

- `hinted_div_rem`: `... q x -> ... q r` (`r` is on top).
- `hinted_div`: `... q x -> ... q`.
- `hinted_rem`: `... q x -> ... r`.
- `mul_by_constant`: `... x -> ... multiplier*x`.
- The hinted API supports negative dividends with a non-negative remainder.
- Values outside Bitcoin's signed-magnitude four-byte Script-number domain are
  unsupported. A mathematically valid operation can therefore still fail if
  `q * divisor` or another intermediate value overflows that domain.

The design is independently implemented from the hint-verification technique
described in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/blob/master/composite-opcodes.md#op_mod-and-op_div).

## Bounded division without quotient hints

Question: can a bounded payload encoding two choices avoid a quotient hint and
lower the live stack, while reusing the arithmetic already present in the
factoradic permutation decoder? `bounded::div_rem(31, 991)` decodes
`x=31*a+b` for `0<=a<32` and `0<=b<31`. It returns `a | b` with `b` on top.
The algorithm is extracted from the existing permutation decoder; this is a
checked public arithmetic boundary, not a claim of a new division algorithm.
The decoder's existing width-4/8/12 metric snapshots remain unchanged.

| Divisor / maximum / fixture | Fragment bytes | Complete leaf bytes | Serialized data witness | Hints / total entry items | Combined peak | Executed non-push ops (leaf) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 31 / 991 / 991 | <!-- metric:scriptint_bounded_pair31_fragment -->85<!-- /metric:scriptint_bounded_pair31_fragment --> | <!-- metric:scriptint_bounded_pair31_leaf -->92<!-- /metric:scriptint_bounded_pair31_leaf --> | <!-- metric:scriptint_bounded_pair31_witness -->4<!-- /metric:scriptint_bounded_pair31_witness --> | 0 / 1 | <!-- metric:scriptint_bounded_pair31_stack -->4<!-- /metric:scriptint_bounded_pair31_stack --> | <!-- metric:scriptint_bounded_pair31_executed -->53<!-- /metric:scriptint_bounded_pair31_executed --> |
| 17 / 271 / 271 | <!-- metric:scriptint_bounded_pair17_fragment -->70<!-- /metric:scriptint_bounded_pair17_fragment --> | <!-- metric:scriptint_bounded_pair17_leaf -->75<!-- /metric:scriptint_bounded_pair17_leaf --> | <!-- metric:scriptint_bounded_pair17_witness -->4<!-- /metric:scriptint_bounded_pair17_witness --> | 0 / 1 | <!-- metric:scriptint_bounded_pair17_stack -->4<!-- /metric:scriptint_bounded_pair17_stack --> | <!-- metric:scriptint_bounded_pair17_executed -->45<!-- /metric:scriptint_bounded_pair17_executed --> |
| 31 / 2^31-1 / 2^31-1 | <!-- metric:scriptint_bounded_full31_fragment -->523<!-- /metric:scriptint_bounded_full31_fragment --> | <!-- metric:scriptint_bounded_full31_leaf -->532<!-- /metric:scriptint_bounded_full31_leaf --> | <!-- metric:scriptint_bounded_full31_witness -->6<!-- /metric:scriptint_bounded_full31_witness --> | 0 / 1 | <!-- metric:scriptint_bounded_full31_stack -->4<!-- /metric:scriptint_bounded_full31_stack --> | <!-- metric:scriptint_bounded_full31_executed -->145<!-- /metric:scriptint_bounded_full31_executed --> |

Matched hinted baselines validate the same canonical bounded dividend,
normalize the hostile quotient with `0 OP_ADD`, then use `hinted_div_rem`.
This preserves canonical outputs while allowing harmless numeric aliases for
the hint under the local consensus profile. All operands and hints coexist at
entry; there is one mandatory quotient hint per invocation in each row below.

| Divisor / maximum / fixture | Fragment bytes | Complete leaf bytes | Serialized data witness | Hints / total entry items | Combined peak | Executed non-push ops (leaf) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 31 / 991 / 991 | <!-- metric:scriptint_hinted_pair31_fragment -->42<!-- /metric:scriptint_hinted_pair31_fragment --> | <!-- metric:scriptint_hinted_pair31_leaf -->49<!-- /metric:scriptint_hinted_pair31_leaf --> | <!-- metric:scriptint_hinted_pair31_witness -->6<!-- /metric:scriptint_hinted_pair31_witness --> | 1 / 2 | <!-- metric:scriptint_hinted_pair31_stack -->8<!-- /metric:scriptint_hinted_pair31_stack --> | <!-- metric:scriptint_hinted_pair31_executed -->35<!-- /metric:scriptint_hinted_pair31_executed --> |
| 17 / 271 / 271 | <!-- metric:scriptint_hinted_pair17_fragment -->36<!-- /metric:scriptint_hinted_pair17_fragment --> | <!-- metric:scriptint_hinted_pair17_leaf -->41<!-- /metric:scriptint_hinted_pair17_leaf --> | <!-- metric:scriptint_hinted_pair17_witness -->6<!-- /metric:scriptint_hinted_pair17_witness --> | 1 / 2 | <!-- metric:scriptint_hinted_pair17_stack -->5<!-- /metric:scriptint_hinted_pair17_stack --> | <!-- metric:scriptint_hinted_pair17_executed -->29<!-- /metric:scriptint_hinted_pair17_executed --> |
| 31 / 2^31-1 / 2^31-1 | <!-- metric:scriptint_hinted_full31_fragment -->44<!-- /metric:scriptint_hinted_full31_fragment --> | <!-- metric:scriptint_hinted_full31_leaf -->53<!-- /metric:scriptint_hinted_full31_leaf --> | <!-- metric:scriptint_hinted_full31_witness -->11<!-- /metric:scriptint_hinted_full31_witness --> | 1 / 2 | <!-- metric:scriptint_hinted_full31_stack -->8<!-- /metric:scriptint_hinted_full31_stack --> | <!-- metric:scriptint_hinted_full31_executed -->35<!-- /metric:scriptint_hinted_full31_executed --> |

Fragment boundary: `fragment-only:` canonical dividend/range checks and quotient
arithmetic, plus hint normalization/verification on the baseline; no input
pushes, output predicates or transaction. Leaf boundary: `complete-leaf:` adds
both exact output comparisons and clean `OP_TRUE`, with the same terminal on
each matched pair. Witness figures serialize the entire data vector, including
its count and length prefixes, excluding script/control block/transaction.
The terminal costs 7/5/9 bytes for these fixtures, with zero cross-component
optimizer delta. Every script is below the 32 KiB cutoff and uses policy `ALL`.

The two smaller direct data-witness maxima are 4 bytes; their hinted baselines
have a 6-byte canonical representative and a 9-byte maximum because a correct
numeric hint may use four raw bytes before normalization. The full-range maxima
are 6 and 11 bytes. A small baseline hint contributes 2 serialized bytes, or
3 bytes as a standalone witness; its maximum contribution is 5 bytes. The
full-range fixture's hint contributes 5 bytes, or 6 as its own witness vector.

The checked API rejects aliases and negative zero even when MINIMALDATA is off.
It validates `0<=x<=maximum` before threshold subtraction. Every subtraction
is guarded by `residual >= divisor*2^bit`; every threshold is at most
`maximum`, and quotient accumulation cannot exceed `maximum/divisor`, so all
arithmetic stays within four-byte operands. Comparison predicates satisfy
tapscript MINIMALIF. The crate-private unchecked core is used only with a
certified residual bound; bypass tests expose invalid remainders outside it.

Stack contract: `caller | x -> caller | quotient | remainder`, with both caller
stacks preserved and no altstack use. Four combined items cover the checked
operation before unrelated state; 996 preserved items plus the one operand
reach the tested 1,000-item peak. One more preserved item rejects. Future inputs
and retained outputs also count, even though this variant uses zero hints.
The baseline is `caller | quotient_hint | x -> caller | quotient | remainder`.

This trades locking bytes for fewer entry items, no hint, and a lower peak.
For the 32-by-31 choice payload, complete-leaf plus data-witness bytes rise
from 55 to 96. No sorting integration or cryptographic property is claimed.
The outputs need a caller's terminal predicate and authentication where required.
The packed payload is this decoder's one operand. If it supplies auxiliary
choices to a sorting protocol, that protocol must count it as one hint; zero
additional arithmetic hints does not imply a protocol without witness data.

Compatibility: the opcodes exist in bare, P2SH, P2WSH and tapscript. Bare script
still requires its opcode/size rules and relay assessment; P2SH additionally
has the 520-byte redeem-script element limit, exceeded by the full-range leaf;
P2WSH retains the 201-opcode limit; tapscript still shares the 1,000-item combined
stack. Local stack-enforced execution is `locally-reproduced` and `unclassified`,
with no complete Bitcoin Core spend or relay-policy validation. The strict
profile uses tapscript, minimal-data off, and stack checks on. The separate raw
helper without `strict` disables the stack limit and is not used here.
The full-range leaf has 229 static non-push opcodes despite only 145 executing
for the measured input, so it exceeds the legacy/P2WSH 201-opcode cap as well.

Reproduce with `cargo test --locked arithmetic::scriptint::bounded --lib`,
`cargo test --locked --test primitive_metrics bounded_division_metrics_are_current -- --nocapture`,
and `cargo test --locked --test primitive_metrics permutation_rank_metrics_are_current`.
Use the repository CI's host optimization settings if desired; Script
compilation still goes through the centralized policy.

See the [knowledge page](../../../knowledge/primitives/scriptnum-bounded-div.md),
[comparison](../../../knowledge/comparisons/arithmetic.md),
[NR-088](../../../knowledge/negative-results/index.md#nr-088-hint-free-bounded-division-loses-combined-bytes),
and [OP-044](../../../knowledge/open-problems.md#op-044-packed-bounded-choice-consumers).

## Zero-hint integer floor roots

[`arithmetic::integer_root::scriptnum_isqrt(bit_count)`](../integer_root/README.md)
consumes one nonnegative numeric input in 1..=31 bits and returns its canonical
floor root. It reuses this module's constant multiplier on derived canonical
root state. Input numeric aliases are allowed when the profile permits them;
callers can compose verify_canonical for a byte-unique contract. The 16/31-bit
fragments measure 232/614 bytes and peak five; every invocation uses one ordinary
data item and zero hints. Existing multiplication/division/canonicality APIs and
catalog evidence remain unchanged.
