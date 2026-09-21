# Selectable HASH160-committed point locks

Question: can one funded legacy P2SH output reveal one of several precommitted
points, while sharing the two ECDSA checks? Yes for small explicit choice sets.
This experiment does not establish a compact 1-of-2,048 digit slot or complete
the ordinary-digest security argument of the underlying point lock.

## Construction

For each candidate, the funder validates `T_i` and derives
`Q_i = -(2C/r0)G - T_i`, rejecting the existing exceptional cases. The holder
publishes `h_i = HASH160(sigma_i)` as in the fixed-point construction. A balanced
IF tree selects the entire `(T_i,Q_i,h_i)` tuple. All tuples are committed in
the redeem script. After selection the stack is `sigma T_i Q_i h_i`:

```text
OP_3 OP_PICK OP_HASH160 OP_EQUALVERIFY
OP_ROT
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP OP_ROT OP_CHECKSIGVERIFY
OP_SWAP OP_CHECKSIG
```

The first line checks the exact selected signature commitment. The remaining
code verifies the same signature under Q_i and T_i; the original constant-digest
extraction argument applies to the selected point. Only two CHECKSIG opcodes
occur in the entire script, regardless of the number of choices.

Alternatively, supply T_i and Q_i as unlocking data and put their HASH160
commitments in the selected leaf. The stack after selection is then
`sigma T_i Q_i HASH160(T_i) HASH160(Q_i) h_i`. Authenticate it with:

```text
OP_5 OP_PICK OP_HASH160 OP_EQUALVERIFY
OP_2 OP_PICK OP_HASH160 OP_EQUALVERIFY
OP_2 OP_PICK OP_HASH160 OP_EQUALVERIFY
```

Then use the same verifier beginning with OP_ROT. The funder still checks the
relationship between each candidate key pair before committing to their hashes.
This alternative adds hash-binding assumptions for the keys and two 33-byte
key items (68 serialized unlocking bytes). All signature commitments stay in
the scriptCode; they are not unauthenticated witness values.

## Measurements

The [choice probe](../../examples/pointlock_choice_probe.rs) compiles through
`compile_with_policy()` and executes every branch of every fitting layout with
`ExecCtx::Legacy`, default options and stack limits enabled. Deterministic
scalar seeds are `[7;32]` through `[7+N-1;32]`. Each accepted branch is also
tested with another candidate's signature; hash-authenticated key layouts
additionally reject a mismatched companion-key opening.

| Choices | Embedded keys | Hash-authenticated keys |
| ---: | ---: | ---: |
| 2 | 196 bytes | 152 bytes |
| 4 | 380 bytes | 284 bytes |
| 5 | 472 bytes | 350 bytes |
| 6 | 564 bytes | 416 bytes |
| 7 | 656 bytes | 482 bytes |
| 8 | 748 bytes | 548 bytes |

These are complete terminal predicates, excluding unlocking serialization,
P2SH funding outputs and transaction framing. Sizes above 520 bytes are
consensus-incompatible as P2SH redeem scripts; those rows are sizing-only and
are not executed. The formulas for these layouts are `92N+12` and `66N+20`.
They are not lower bounds for all possible constructions. Five choices fit
with embedded keys, or seven with key hashes. Seven choices encode less than
three bits; 2,048 choices would be needed for an 11-bit digit.

One signature is supplied per invocation. Embedded-key layouts require one
or two selector items for N=2 or N=4, and two or three for N=5. Key-hash layouts
require one selector for N=2, two for N=4, and two or three for N=5,6,7. Treating
selectors as hints, these are respectively 1, 2, and 2–3 hint items, all present
at entry. Key-hash layouts also require two mandatory public-key opening items
(not auxiliary hints). Total initial item counts are 2, 3, or 3–4 with embedded
keys and 4, 5, or 5–6 with key hashes. Measured combined stack peaks are five
and seven respectively; no altstack is used. The complete P2SH scriptSig adds
one redeem-script push. Legacy input witnesses are empty. These small layouts
fit the 1,000-item stack bound; no repeated multi-slot configuration is measured.

Evidence: `locally-reproduced` for compiled sizes and legacy predicate execution;
`inspected` for the conditional extraction argument. Deployment: `unclassified`
for fitting layouts, pending complete transaction/Core validation. The original
ordinary-digest security question remains open.

```sh
cargo run --locked --example pointlock_choice_probe
```

## Scaling boundary

A compact authenticated set could avoid listing every candidate in the script,
but a standard concatenation-based Merkle proof cannot be implemented simply
by placing siblings in the witness: legacy Script lacks enabled concatenation
and slicing to bind the child and sibling into each parent preimage. This does
not prove that every succinct membership construction is impossible. Building
and validating such a mechanism, preserving the key relationship and signature
commitment's role in the ordinary digest, is the unresolved large-N problem.


Primary rule references: [BIP16's redeem-script size limit](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#520-byte-limitation-on-serialized-script-size)
and [Bitcoin Core 30.3 interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
for disabled concatenation/slicing opcodes and legacy signature checking.
