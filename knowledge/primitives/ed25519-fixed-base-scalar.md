# Ed25519 fixed-base scalar multiplication

## Question and objective

Can a hostile canonical scalar be mapped to `[s]B` with one generated
Tapscript fragment while keeping both the serialized script below four million
bytes and the combined main-plus-alt-stack population at or below 1,000 items?
The current construction optimizes the exact G29 fixed-base schedule for those
two bounds. It is a group primitive, not an Ed25519 signature verifier.

## Construction

The scalar is eight compressed-u32 ScriptNum items. Script first proves
`0 <= s < l`, where `l` is the Ed25519 subgroup order, and then streams a
253-bit centered-window recoding from most significant group to least. The
G29 layout has 29 position groups: eight low width-8 groups, twenty lower
width-9 groups, and one top width-9 group. The top table initializes the
accumulator; the remaining 28 groups each run one affine transition.

Every table is an MSB-first bit decision trie. The scalar streamer derives and
retains the digit sign while the corresponding lower non-identity leaf
authenticates the digit magnitude and the constants

```text
C+ = a+b, C- = b-a, K = (d*a*b)^-1.
```

Width-9 leaves emit packed `C+` and `C-` plus 13 direct K limbs. Width-8 leaves
emit both coordinate constants as direct 51-digit fields as well, because that
table growth is repaid by smaller transition kernels. The zero digit's table
leaf emits the normalized synthetic tuple
`C+=C-=K=1` and nonzero zero; its scalar-derived sign is also zero. The
signed/identity relation wrapper swaps `C+` and `C-` for negative digits,
negates the shared tau limbs after its first relation, and proves a zero digit
as `tau=0` and `next=current`. The exact bit-trie table serialization is
923,727 unoptimized bytes and uses no witness hints.

For current `(x,y)`, selected magnitude point `(a,b)`, and claimed next
`(x',y')`, each transition verifies three exact field relations:

```text
x*y       - K*tau     = 0 mod p
(x'+y') + (x'-y')*tau - (x+y)*C+ = 0 mod p
(x'-y') + (x'+y')*tau - (x-y)*C- = 0 mod p
```

where `p=2^255-19`. The pseudo-Mersenne fold is performed inside each
coefficient recurrence. One integer quotient closes each relation, so the
schedule needs three logical quotient hints per transition rather than field
multiplication carry vectors.

## Witness and hint accounting

The byte-minimizing direct-quotient configuration has this complete fragment
entry:

| Entry class | Items | Hint status |
| --- | ---: | --- |
| Packed `tau,next.x,next.y` trace, 24 per transition | 672 | circuit data, not hints |
| Relation quotients, 3 per transition | 84 | witness hints |
| Packed scalar | 8 | primary input, not hints |
| **Total** | **764** | **84 hints** |

All 764 items coexist at script entry. Each honest quotient fits a signed
23-bit slot and therefore uses at most three ScriptNum payload bytes; it is not
a full 32-bit hint. The focused all-extreme 84-hint vector serializes to 337
bytes including its item count and per-item lengths. That is a hint-only
fixture, not the unmeasured complete 764-item witness. The exact bounded
integer equation `H=q*p` uniquely binds q, so the integrated byte-minimizing
path does not separately range-check the 84 items. A value longer than four
bytes fails when consumed by Script arithmetic; a nonminimal at-most-four-byte
alias denotes the same integer and is a policy/malleability issue, not an
alternate solution to the relation.

There is also a minimum-item packed Pareto point. It carries the same 1,932
logical quotient bits in 61 physical compressed-u32 items, reducing complete
entry from 764 to 741. Its decoder is 23,769 policy-compiled bytes and 25,570
bytes in a multi-megabyte unoptimized leaf, its deterministic hint witness is
222 serialized bytes, and its focused strict execution peaks at 762 items.
Direct quotients spend 23 more initial items to remove those 25,570 locking
bytes, which is the better trade near the block-size frontier.

## Evidence and measured boundary

Evidence is `locally-reproduced`; deployment is `unclassified`. The generated
actual fragment serializes the canonical-scalar validator, real scalar stream,
29 authenticated tries, sign/identity routing, all trace and direct-quotient
consumption, and all 28 real affine kernels. The three signed kernel generators
compile their smaller boundary-preserving semantic steps through the
repository policy; the final multi-megabyte composition is then serialized
with `CompileOptions::NONE`. It returns a 102-item certified expanded affine
point.

| Actual serialized component | Raw bytes |
| --- | ---: |
| 29 identity-safe bit tries | 923,727 |
| 28 signed/identity affine kernels | 2,940,987 |
| Canonical scalar validator | 791 |
| Scalar stream, sign, and packet routing | 15,897 |
| **Integrated fragment** | **3,881,402** |

Step precompilation removes 78,498 bytes without changing the witness or stack
contract. The integrated script has 118,598 bytes of nominal room below four
million before any terminal point consumer. That comparison is only a
script-size objective; four million is not itself a Bitcoin script or
transaction limit.

The strict whole-schedule run keeps the real scalar validation, selection,
control, and routing but substitutes peak-equivalent bodies for the 28 large
arithmetic kernels. Individual positive, negative, and identity transition
kernels were executed separately under the strict 1,000-item harness. Scalars
zero, one, and `l-1` all pass the integrated stubbed schedule at an exact
993-item combined peak. The maximum is the first transition: 737 preserved
items plus its 256-item measured local peak. The optimized signed kernels were
regenerated in measure-only mode; their Script execution and the full
integrated arithmetic schedule were deliberately not run because generated
long-running tests are opt-in. Thus the bytes are an actual integrated
serialization, while the integrated stack result is a stubbed strict execution
backed by the pre-step-compilation separately measured kernel peaks.

This is a `fragment-only` boundary. Input pushes, complete witness
serialization, a terminal consumer or point comparison, clean-stack truthy
predicate, tapleaf/control-block serialization, complete transaction context,
executed-opcode and validation-weight measurements, and Bitcoin Core
differential validation are excluded.

For scale only, a conservative serialization of the 764 arguments is 4,416
bytes excluding the witness-vector count. An inspected depth-zero taproot
projection is 3,885,860 witness bytes and 3,886,238 WU for a one-input,
one-P2TR-output transaction before adding the missing terminal consumer or
reserving block-level overhead. That leaves 113,762 WU below the block limit in
the isolated model. These are projections, not complete-leaf or
complete-transaction measurements.

## Security and deployment boundary

- The scalar validator binds the eight hostile words to exactly `0 <= s < l`.
- Trace fields are hostile and are decoded/canonicalized by the transition
  wrappers; all 84 quotients are bound by the exact integer recurrences.
- The validated scalar stream derives the sign and magnitude in one callback;
  that magnitude selects the table constants and identity/nonzero control, so
  the sign and selected leaf remain bound to the same digit. The deterministic
  table generator, including its fixed-point arithmetic, has not been
  independently differentially validated.
- The fragment is tapscript-oriented. Its size and opcode count exceed legacy
  and P2WSH limits, and its size alone exceeds the 400,000-WU standard
  transaction limit. A four-million-byte script is not a four-million-byte
  transaction allowance: transaction, witness-vector, and taproot control data
  also consume the 4,000,000-WU consensus block limit.
- No complete tapscript transaction has been validated against Bitcoin Core,
  so fitting the two modeled fragment bounds is not a consensus-deployment
  claim.

## What remains for EdDSA

This primitive computes only fixed-base `[s]B`. Complete RFC 8032 verification
still needs canonical compressed-point decoding, curve and subgroup/small-order
policy, SHA-512 challenge construction and scalar reduction, a variable-base
`[h]A` path or another proof of the double-scalar equation, final point
comparison, and complete transaction validation. It therefore provides no
EdDSA acceptance claim by itself.

For the custom BLAKE3 direction, a key-specialized transcript
`BLAKE3(D32 || A32 || R32 || M32)` can precompute the fixed first block and
perform one 65,208-byte compression in Script. It uses 128 checked data items,
exactly zero hint items, and an analytic local peak of at most 591. Together
with this fixed-base fragment the raw byte subtotal is 3,946,610 before routing
or curve glue, but naive composition exceeds the stack limit. An inspected
carrier model instead embeds the 64 `R32||M32` bytes into the unused high bits
of 64 existing q items. It retains 84 logical hint items and the 764-item entry,
and projects roughly 3.957 MB at the same 993-item frontier; its final metric
run was deliberately skipped. More importantly, the best inspected joint
`[s]B-[h]A` schedule for the current affine certificate is near 7.59 MB and
needs at least 1,701 trace/hint packet items. This is a scoped architecture
result, not a proof that no different verification system can fit.

The separate Montgomery slope successor changes that certificate rather than
extending this affine trace. Its current G32/H16 leaf verifies the complete
custom `[s]B-[h]A=R` equation with 47 one-coordinate transitions, derives all
relation quotients in Script, and has 803 coexisting entry-data items with
exactly zero auxiliary hints. It remains a fixed-key, fixed-message BLAKE3-128
benchmark—not RFC 8032 or transaction authorization—and does not upgrade this
standalone G29 fixed-base primitive's evidence or deployment class. See the
[slope verifier page](ed25519-blake3-montgomery-slope.md) for its distinct
boundary.

See the [integrated generator](../../examples/ed25519_g29_fixed_base_integrated.rs),
the [transcript-carrier model](../../examples/ed25519_g29_transcript_carrier_model.rs),
the [affine-kernel implementation notes](../../src/curves/ed25519/README.md),
the [base-field primitive](ed25519-field.md),
[negative result NR-031](../negative-results/index.md),
[negative result NR-032](../negative-results/index.md), and
[open problem OP-018](../open-problems.md).
