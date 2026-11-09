# Joint u32 residues modulo 7 and 9

`arithmetic::u32::dual_residue::u32_residues_7_9()` takes a canonical
four-item big-endian u32 word and returns its remainders modulo 7 and 9.
Every witness byte limb is checked for range and canonical encoding before
arithmetic. There are no generation-time parameters.

## Script metrics

| Word | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `01234567` | Shared mod 63 | <!-- metric:dual_residue_fused_low_script -->210<!-- /metric:dual_residue_fused_low_script --> | <!-- metric:dual_residue_fused_low_witness -->9<!-- /metric:dual_residue_fused_low_witness --> | 4 | 0 (none) | <!-- metric:dual_residue_fused_low_stack -->7<!-- /metric:dual_residue_fused_low_stack --> | <!-- metric:dual_residue_fused_low_executed -->115<!-- /metric:dual_residue_fused_low_executed --> |
| `01234567` | Separate | <!-- metric:dual_residue_separate_low_script -->248<!-- /metric:dual_residue_separate_low_script --> | <!-- metric:dual_residue_separate_low_witness -->9<!-- /metric:dual_residue_separate_low_witness --> | 4 | 0 (none) | <!-- metric:dual_residue_separate_low_stack -->10<!-- /metric:dual_residue_separate_low_stack --> | <!-- metric:dual_residue_separate_low_executed -->136<!-- /metric:dual_residue_separate_low_executed --> |
| `fedcba98` | Shared mod 63 | <!-- metric:dual_residue_fused_high_script -->210<!-- /metric:dual_residue_fused_high_script --> | <!-- metric:dual_residue_fused_high_witness -->13<!-- /metric:dual_residue_fused_high_witness --> | 4 | 0 (none) | <!-- metric:dual_residue_fused_high_stack -->7<!-- /metric:dual_residue_fused_high_stack --> | <!-- metric:dual_residue_fused_high_executed -->113<!-- /metric:dual_residue_fused_high_executed --> |
| `fedcba98` | Separate | <!-- metric:dual_residue_separate_high_script -->248<!-- /metric:dual_residue_separate_high_script --> | <!-- metric:dual_residue_separate_high_witness -->13<!-- /metric:dual_residue_separate_high_witness --> | 4 | 0 (none) | <!-- metric:dual_residue_separate_high_stack -->10<!-- /metric:dual_residue_separate_high_stack --> | <!-- metric:dual_residue_separate_high_executed -->136<!-- /metric:dual_residue_separate_high_executed --> |

Both leaves include all byte checks, the two output checks and terminal true.
The whole leaf uses optimizer `ALL`. Witness bytes include the item count
and length prefixes for all four canonical byte limbs. They exclude script,
control block, annex and transaction. All four items coexist at entry.
The opcode trace counts active non-push operations and encountered branch
delimiters. No signatures execute.

## Security

The two residues identify a class modulo 63. Inputs that differ by 63 can
produce the same pair, so a caller that depends on the original u32 must
bind it separately. There is no key or cryptographic authentication.

## Script compatibility and standardness

The opcodes exist in bare script, P2SH, P2WSH and tapscript. The first
three complete script contexts are unclassified. Measurements use the
local tapscript `Consensus` profile, enforcing stack and element limits and
MINIMALIF, with numeric minimality and experimental OP_CAT off. Evidence is
`locally-reproduced` and execution is `unclassified`. See
[script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Witness and hints

Four ordinary items encode the bytes in most-significant-first order.
Each byte is a canonical nonnegative ScriptNum in `0..=255`, including a
sign pad for bytes from 128 through 255. There are no hint items or bytes.
Preloaded future invocations contribute all their items to the peak.

## Stack contract

`caller | b0 b1 b2 b3 -> caller | r7 r9`. The altstack is unused.
Budget seven combined items plus all preserved caller state. Consume or
check both outputs and add a terminal predicate for a complete leaf.

## Operational notes and knowledge-base integration

See the [research note](../../../../knowledge/primitives/u32-dual-residue.md)
for the arithmetic bounds, comparison, negative result and test commands.
The catalog entry is `arithmetic/u32-dual-residue`.
