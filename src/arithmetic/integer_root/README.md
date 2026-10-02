# Integer floor roots over ScriptNum

`arithmetic::integer_root::scriptnum_isqrt(bit_count)` consumes one hostile
nonnegative four-byte ScriptNum and returns its canonical floor square root.
It tries fixed root bits using the residual `x-r*r` and differences `2*r*b+b*b`,
reusing `scriptint::mul_by_constant`. No variable multiplication/division,
table or witness hint is needed. Both caller stacks are preserved. The caller
binds the returned data and supplies a terminal predicate and authorization.

## Parameters

`bit_count`: generation-time integer in `1..=31`, no default. Input is
numerically in `0..=2^bit_count-1` and at most four bytes. Constructor rejects
0, 32 and larger widths; a positive input 2^31 needs five ScriptNum bytes and
is outside this representation. Numeric aliases and negative zero are accepted
when the execution profile permits nonminimal numbers. Use the existing
`scriptint::verify_canonical()` before this fragment for byte-unique inputs.

## Script metrics

Fragment includes both numeric guards, all root trials and residual cleanup;
excludes witness pushes and terminal predicate. Leaf checks the exact canonical
root then TRUE. Witness includes count/length prefixes and the ordinary input;
excludes script/control block/annex/transaction. Every invocation has zero hint
items and zero hint bytes; all data coexist at entry.

| Configuration | Fragment | Exact-root leaf | Serialized witness | Combined peak |
| --- | ---: | ---: | ---: | ---: |
| 16 bits, x=65,535 / r=255 | <!-- metric:scriptnum_isqrt16 -->232<!-- /metric:scriptnum_isqrt16 --> | <!-- metric:scriptnum_isqrt16_leaf -->237<!-- /metric:scriptnum_isqrt16_leaf --> | 5 | 5 |
| 31 bits, x=2,147,483,647 / r=46,340 | <!-- metric:scriptnum_isqrt31 -->614<!-- /metric:scriptnum_isqrt31 --> | <!-- metric:scriptnum_isqrt31_leaf -->620<!-- /metric:scriptnum_isqrt31_leaf --> | <!-- metric:scriptnum_isqrt31_witness -->6<!-- /metric:scriptnum_isqrt31_witness --> | <!-- metric:scriptnum_isqrt31_stack -->5<!-- /metric:scriptnum_isqrt31_stack --> |

The 31-bit fragment has <!-- metric:scriptnum_isqrt31_static -->503<!-- /metric:scriptnum_isqrt31_static -->
static non-push opcodes; its leaf has 504. Executed counts are unavailable:
instruction position includes pushes/inactive branches. No signatures execute;
charged signature weight zero is recorded separately and is not a complete
transaction-budget measurement. Setup/table bytes are zero; state initialization
and cleanup are included in the whole fragment.

All scalar public scripts use ALL. Matched threshold dispatch measures
18/34/70/147/2,989 bytes at widths 1/4/6/8/16 versus restoring
27/48/72/99/232, so it wins small widths. At 24/31, dispatch measures
54,109/659,112 bytes explicitly unoptimized NONE, versus restoring 405/614 ALL.
Its peak is 3 rather than 5. No universal dominance is claimed. The report
records each raw size, policy options, final hashes and exact execution profile.

Every allowed numeric input can be serialized in four bytes when aliases are
permitted. Allowed witness maximum is 6 bytes for one input, including framing;
canonical fixtures can be smaller. A root-only leaf does not fix one unique
input or encoding. Local Policy rejects nonminimal aliases with MinimalData.

All-entry independent 31-bit folds are measured after compiling the whole
script. Two folds: fragment/leaf 1,230/1,235 bytes, witness 4 bytes, 2 ordinary
data items / 0 hints and peak 6. Thirty-two: 19,710/19,803 bytes, witness 89,
32 data / 0 hints and peak 36. Both use ALL. For these fragments the component
sums 1,232/19,712 plus whole optimizer delta -2 give the final bytes.
At 996 folds the 615,528-byte fragment / 618,389-byte leaf are explicitly
unoptimized NONE, witness 2,738, 996 ordinary data / 0 hints, peak 1,000.
Individually ALL-compiled components sum to 613,536; whole-policy delta +1,992
includes the policy change to NONE. It is not cross-component optimizer loss
alone. Raw component sum is 615,528. A 997th fold fails StackSize at 1,001.
Allowed witness maxima are 11/161/4,983 bytes for 2/32/996 inputs; future inputs
and parked roots are counted. Every scalar invocation uses a fresh root state.

The 53-root fragment has raw size 32,754 and final size 32,646 with ALL; its
exact-output leaf has raw/final size 32,903 with NONE, explicitly unoptimized.
Adding 149 raw predicate bytes therefore changes final size by 257 because the
whole compilation policy changes. Both use 53 ordinary data items, zero hints,
142 fixture witness bytes (allowed maximum 266), and peak 57. At 54 roots,
fragment/leaf are 33,372/33,525, both unoptimized NONE. Fragment compilation
options must not be inherited by a composed leaf.

## Security

No cryptographic security parameter or one-time-key assumption exists. The
numeric guards prove domain membership; they do not bind input bytes. Root r
implies `r*r<=x<(r+1)^2` only within the checked input domain. A literal root
check accepts multiple numeric x values except at some degenerate intervals,
plus aliases when allowed; it does not authenticate an input or its provenance.
Retain/bind x separately when a protocol needs it.

Arithmetic argument: root-bit count k<=16. Before trying b, r is a multiple
of 2b in `0..=2^k-2b`. First delta at k=16 is 2^30; maximum later delta is
`5*2^28=1,342,177,280`. Every double-and-add intermediate fits four-byte numeric
arithmetic. Subtract only when residual>=delta; residual stays nonnegative and
`residual=x-r*r` survives. Accepting high-to-low bits therefore yields the exact
floor root without forming an overflowing whole candidate square. This is a
local mathematical argument supported by exhaustive domains and square edges,
not a Bitcoin Core or cryptographic security claim.

## Script compatibility and standardness

- **Bare/legacy:** enabled stack/numeric opcodes. The 16-bit fragment/leaf have
  191/192 static non-push opcodes and fit isolated 201-opcode/10,000-byte bounds;
  smaller leaves still require complete-context validation. The 31-bit leaf
  exceeds the legacy opcode bound.
- **P2SH:** the representative 16-bit leaf is 237 bytes, below 520; the 31-bit
  leaf is 620, above the redeem-script limit and legacy opcode bound.
- **P2WSH:** the 31-bit leaf exceeds the 201-opcode bound; large repeated leaves
  also exceed the 10,000-byte script bound.
- **Tapscript:** explicit local Consensus profile enforces 520-byte elements,
  combined 1,000-item limit and MINIMALIF; numeric minimality off, OP_CAT off,
  CLTV/CSV checks on, synthetic empty transaction/data-only budget, no signatures.
  All branch predicates are canonical. Local Policy additionally checks minimal
  numbers and an 80-byte initial-element cap; it is a partial policy probe.

Every catalog configuration is locally-reproduced/unclassified. No funded
transaction, Taproot commitment, full relay acceptance or Core differential is
established. See [script types](../../../docs/script-types.md),
[standardness](../../../docs/standardness.md) and
[execution profiles](../../support/README.md#explicit-fragment-profiles).

## Witness and hints

One ordinary at-most-four-byte ScriptNum item x; no secret requirement.
Exactly **0 hint items / 0 hint bytes per invocation**. For r preloaded folds,
ordinary data total r and hints total `r*0=0`, all at entry. Numeric aliases
remain allowed under the stated profile; output r is canonical. Serialized
allowed maxima are `5*r+CompactSize(r)`. Input/root values are data, not hints.

## Stack contract

Main: `caller | x -> caller | canonical floor_root(x)`.
Altstack: caller state is preserved. Solo numeric peak is 5 including the input;
add every caller main/alt item. One fold leaves room for 995 caller items.
Canonical-input wrappers still peak at 5 for restoring; canonical threshold
wrappers peak at 4 rather than the numeric threshold schedule's 3. The suite
observes every preserved byte at exactly 1,000 and rejects one extra item.
For r preloaded public roots, peak is r+4 plus both caller stacks; 996 has no
extra caller capacity. Zero root is valid data but a false bare predicate;
consume it in the required exact-result check and terminal predicate.

## Operational notes

The shared suite covers both schedules and both canonical-input compositions using the existing
verify_canonical helper:
all 65,536 16-bit inputs per family, every 31-bit square endpoint for the public
schedule, deterministic interiors, numeric aliases, hostile/short inputs at
every scalar and repeated position, exact main/alt frontiers, every preloaded
output and separate Policy precedence. Actual compiled range/canonicality and
terminal bypasses preserve valid controls and trigger the same typed assertion.
Root-trial equality and output-order mutations trigger the same exact-result
assertion. Source bytes match the original prototype at every width 1..=31.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test integer_root_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics scriptnum_isqrt_metrics_are_current
python3 research/integer-root-bounds/verify_metrics.py
python3 research/integer-root-bounds/verify_probe.py
python3 tools/kb.py validate
```

The [source-pinned guide](../../../research/integer-root-bounds/README.md)
separates the untouched original prototype from the integrated implementation.
Integer square root is established; the local result is this Script scheduling
and composition comparison. Linux's pinned shift/subtract source is context,
not ported code. The independent Python oracle uses exact math.isqrt.

## Knowledge-base integration

Catalog `arithmetic/scriptnum-isqrt`; [primitive](../../../knowledge/primitives/scriptnum-isqrt.md),
[arithmetic comparison](../../../knowledge/comparisons/arithmetic.md),
[composition](../../../knowledge/techniques/composition.md#preloaded-integer-roots),
[NR-080](../../../knowledge/negative-results/integer-root-bounds.md) and
[OP-038](../../../knowledge/open-problems.md#op-038--unsigned-word-integer-root-frontier).
