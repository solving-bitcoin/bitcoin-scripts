# Exact u4 products through quarter squares

Question: can a 31-entry quarter-square table replace the full product grid for
canonical nibble pairs, reducing lifecycle script size and combined stack use?
The identity is already used by the repository's secp256k1 field backend; this
is a small-domain specialization, with no mathematical or global novelty claim.

`quarter_square::u4_pairwise_mul_exact(n)` accepts n=1..483 (no default) and maps
`preserved | a[0] b[0] ... a[n-1] b[n-1]` to ordered `a[i]*b[i]` outputs.
All inputs must be canonical ScriptNums in 0..15. Outputs are canonical
ScriptNums in 0..225, so 128..225 require two bytes and are not raw one-byte
serialization. No terminal predicate, cryptographic authentication or hints
are supplied. Caller main/alt state is preserved.

Let `Q(x)=floor(x*x/4)`, x=0..30. Because a+b and a-b have the same parity,
the floors' remainders cancel, giving `Q(a+b)-Q(abs(a-b))=a*b`. The script
checks both operands before lookup, parks abs difference on altstack, looks
up Q(sum), then adjusts the difference index for that live result and subtracts
Q(difference). The private 31-entry table stays in place during the batch.
Inputs are routed from below it in reverse pair order; outputs parked on the
altstack are restored in original order after table cleanup.

## Reproduced costs

| Pairs | Quarter fragment / leaf / peak | Full exact fragment / leaf / peak | Data items | Hint items | Serialized data witness |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 118 / 122 / 36 | 635 / 639 / 261 | 2 | 0 | 5 |
| 2 | 159 / 166 / 38 | 677 / 684 / 263 | 4 | 0 | 9 |
| 8 | 405 / 430 / 50 | 929 / 954 / 275 | 16 | 0 | 33 |
| 32 | 1389 / 1486 / 98 | 1937 / 2034 / 323 | 64 | 0 | 129 |
| 128 | 5325 / 5710 / 290 | 5969 / 6354 / 515 | 256 | 0 | 515 |
| 370 | 15247 / 16358 / 774 | 16133 / 17244 / 999 | 740 | 0 | 1483 |
| 483 | 19880 / 21330 / 1000 | unsupported | 966 | 0 | 1935 |

Each row uses 2n canonical sevens, all operands at entry, zero hints per
invocation and zero cumulative hints in every batch. Fragment-with-memory
includes one table setup, all canonical/range checks, routing, queries, cleanup
and every ordered product; input pushes and terminal checks are excluded on
both sides. Complete leaves compare every reverse output against 49 through
`OP_EQUALVERIFY`, then `OP_TRUE`. Witness bytes serialize only the complete
data vector; leaf/control block and transaction weight are excluded.
Combined main-plus-alt peak is measured on the exact recorded leaf.

The full exact baseline uses its own canonical row-index query and a 256-entry
exact product table. It does not redefine the existing modulo-table API.
At n32 the quarter method saves 548 bytes and 225 peak items; the full exact
row uses 1937 bytes and 323 items. Both operate on 64 ordinary data items and
zero hints. Static non-push counts are 1008 versus 1088 at n32, but at n370 the
quarter method has 11486 versus 11228; dynamic counts and validation weight are
unavailable. Claims of lower size/stack therefore do not imply fewer executed
operations. All measured scripts/leaves are below the 32KiB raw cutoff and
receive centralized `CompileOptions::ALL`.

The quarter peak is `2*n+34+preserved_items`, so n483 leaves no caller room.
Full-table peak is `2*n+259+preserved_items`, allowing n370 plus one live item.
Contracts check exact 1000 acceptance and StackSize rejection at 1001 with
observable runtime outputs and caller stacks.

## Modulo variant is a separate result

Storing Q modulo 16 and adding 16 to a negative difference returns the modulo
product, but adds a conditional normalization per query. At n32 it costs
1583 bytes/98 items versus 1792/323 for the canonical full modulo table;
at n128, 6191/290 versus 6016/515; at n370, 17807/774 versus 16664/999.
The modulo quarter method retains its memory advantage but loses script size
on the latter two measured batches. It remains a research-only comparison:
[NR-076](../negative-results/u4-quarter-square-modulo.md). Exact products and
modulo products are different operations. The existing numeric-only modulo
query additionally accepts aliases; it is audited separately by the contracts.

## Evidence and provenance

All rows are `locally-reproduced` / `unclassified`. Cost runs use strict local
tapscript, `Options::default` with stack checks, synthetic empty transaction
and data-only budget, no signatures. Hostile-witness/resource contracts also
use local `TapscriptProfile::Consensus`, disabling minimal-number policy and
CAT while retaining stack and minimal-IF checks. No Core transaction or relay
policy evidence is claimed. Bare/P2SH/P2WSH use compatible opcodes, but their
separate limits remain applicable; n32's 1008 static non-push opcodes exceed
the 201-opcode bound, and P2SH adds the redeem-script element bound. Tapscript
stack acceptance alone does not establish deployability.

[Source](../../src/arithmetic/u4/quarter_square.rs), [README](../../src/arithmetic/u4/README.md),
[shared contracts](../../tests/u4_product_contract.rs),
[producer](../../examples/u4_quarter_square_probe.rs), and
[manifest/report](../../research/u4-quarter-square/README.md) bind configuration,
terminal boundary, exact script/witness hashes and dependency pins. Complete
Core/policy differential evidence remains [OP-034](../open-problems.md#op-034--complete-quarter-square-product-oracle).
