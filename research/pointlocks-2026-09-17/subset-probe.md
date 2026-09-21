# Small threshold subsets of committed point locks

Question: can a single legacy P2SH redeem script authenticate a strictly sorted
`t`-element subset of `n` committed point-lock candidates while storing each
candidate only once? This probe measures a straightforward shared-table layout;
it does not establish optimal sizes or complete the underlying ordinary-digest
security argument.

[Source](../../examples/pointlock_subset_probe.rs) uses the same deterministic
candidate scalars `[7;32]` through `[7+n-1;32]` as the earlier choice probe. The
funder derives and validates each companion public key using the existing
point-lock helper. The redeem script stores three HASH160 commitments per
candidate: target key, companion key, and complete signature including flag.

Each selected opening supplies `(signature, target, companion, index)`.
The script authenticates all three openings at that index using `OP_PICK`,
checks the existing signature-length guard and both ECDSA equations, and requires
strictly increasing indices in `[0,n)`. The table is pushed once, reused for
all selected candidates, and removed before the final `OP_TRUE`. Sorted indices
prevent one revelation from being counted repeatedly; the script accepts exactly
`t` distinct candidates with the supplied complete unlocking shape.

## Measured configurations

Compiled with `ScriptCompilation::compile_with_policy()`. Predicate execution
uses `ExecCtx::Legacy`, default interpreter options, input index 1 and one output
(the native legacy SINGLE-bug digest). The default stack, element-size and opcode-count checks remain enabled. The
interpreter defaults enable experimental OP_CAT, but this script contains none;
no experimental opcode is used. Successful runs also require one final stack item.
Only scripts at most 520 bytes are executed. Complete funding/spending
transactions and Bitcoin Core validation are not included.

| n | t | Subsets | Redeem bytes | Static non-push ops | Max scriptSig bytes | Combined stack peak |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 1 | 2 | 190 | 52 | 322 | 13 |
| 2 | 2 | 1 | 248 | 100 | 510 | 17 |
| 3 | 1 | 3 | 254 | 53 | 386 | 16 |
| 3 | 2 | 3 | 312 | 101 | 575 | 20 |
| 3 | 3 | 1 | 370 | 149 | 763 | 24 |
| 4 | 1 | 4 | 319 | 55 | 452 | 19 |
| 4 | 2 | 6 | 377 | 103 | 640 | 23 |
| 4 | 3 | 4 | 435 | 151 | 828 | 27 |
| 5 | 1 | 5 | 387 | 56 | 520 | 22 |
| 5 | 2 | 10 | 449 | 104 | 712 | 26 |
| 5 | 3 | 10 | 511 | 152 | 904 | 30 |
| 6 | 1 | 6 | 452 | 58 | 585 | 25 |
| 6 | 2 | 15 | 514 | 106 | 777 | 29 |
| 7 | 1 | 7 | 516 | 59 | 649 | 28 |

`scriptSig` byte counts include all selected signature/key/index pushes and the
redeem-script push, using actual rust-bitcoin Builder serialization and minimal index pushes
(OP_0 through OP_6), but exclude the surrounding
CompactSize scriptSig length and other input/transaction fields. Signatures for
these deterministic scalars are 60 bytes. All point-lock input witnesses are
empty: no witness data bytes, or one byte for the empty-vector serialization if
these inputs appear in a transaction containing other SegWit inputs.

The 3-of-6, 2-of-7 and 3-of-7 layouts compile to 576, 578 and 640 bytes. They are
sizing-only, `consensus-incompatible` as P2SH redeem scripts due to the 520-byte
limit, and are not executed. Their static non-push counts are 154, 107 and 155.

Every accepted subset of every fitting row is tested. Each subset also rejects
another candidate's signature, target key or companion key, negative and
out-of-range indices, and (where t>=2) duplicate or descending selections.
All tests passed in the focused example invocation:

```sh
cargo run --locked --example pointlock_subset_probe
```

Evidence: `locally-reproduced` for compiled bytes and local Legacy predicate
execution. Deployment: `unclassified` for fitting rows pending complete
transaction/Bitcoin Core checks. Compiler pin `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`;
interpreter pin `702544c9a045ac4fc14846da6da6559e2b7cd9d1`.

## Stack and composition boundary

The exact hint count is `t` index items per invocation: 1, 2 or 3 in this probe.
The two public-key openings per selection are mandatory authenticated data,
not counted as auxiliary hints. Together with `t` signatures there are `4t`
initial data items, all coexisting at script entry; a complete P2SH scriptSig
adds the redeem-script push as one further item before P2SH evaluation.
The peak includes both main and alt stacks, the `3n` table entries, remaining
opening records, the previous index, and temporary lookup values. Every fitting
row remains below Bitcoin's 1,000 combined-item limit. Each separate P2SH input
has its own evaluation stack; this does not imply that arbitrary concatenation
of many pools into one script is possible.

The table is reused but the two-CHECKSIG verifier is unrolled `t` times, so there
are `2t` signature checks. This is subset publication, not yet an implementation
of HORS message hashing, one-time-signature verification, or a BitVM3 protocol.
Compare [the conceptual subset analysis](hors-subsets.md).
