# Binohash legacy CODESEPARATOR and FindAndDelete fixture

This funded legacy P2SH experiment differentially validates the interaction
between an executed `OP_CODESEPARATOR`, an unexecuted separator in a dead
branch, and `FindAndDelete` of a selected signature push.

The redeemScript has two selection branches. One supplies its fixed pool
signature before the always-executed separator, so that push lies outside the
operative scriptCode. The other supplies a distinct fixed pool signature after
the separator, so `FindAndDelete` removes its canonical push from the operative
suffix. A later `OP_CODESEPARATOR` is inside `OP_0 OP_IF ... OP_ENDIF`: it is
not executed and therefore does not replace the operative boundary, but legacy
sighash serialization still omits its separator opcode from the chosen suffix.

## Evidence

Two disjoint funded spends are `differentially-validated` against Bitcoin Core
v30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`. Core accepted both
locally signed transactions in blocks. For each selected position, Core
rejected four independently signed controls: using the complete redeemScript as
scriptCode, treating the dead separator as executed, retaining the dead
separator opcode in the serialized scriptCode, and applying the wrong
`FindAndDelete` set. The comparison is indirect: Core verifies ECDSA signatures
over its digest; no RPC exposes the digest itself.

The primary source pin is that commit's `src/script/interpreter.cpp`: lines
320-332 and 1137-1146 construct the suffix and apply `FindAndDelete`, lines
1047-1055 update the boundary only in the executed opcode case, and lines
1266-1287 omit parsed separator opcodes during legacy serialization. Source
record `bitcoin-core-v30.3-legacy-sighash` preserves the immutable URL and
inspection date.

The 23-byte P2SH locking script commits to a 229-byte redeemScript. Each valid
two-input, one-output legacy transaction weighs 1,780 WU and has 2-byte and
306-byte scriptSigs. It has zero witness items and zero auxiliary hint items.
Combined stack peak and executed opcode count are unmeasured. The
[checked report](../../tests/data/binohash-codesep-v30.3.json) records exact
transactions, decoded sizes, Core verdicts, separator offsets, signing-script
views, release hashes, and negative controls.

Both valid spends fail default relay policy with `Using OP_CODESEPARATOR in
non-witness script` under `CONST_SCRIPTCODE`. This observed first failure does
not separately test which policy error would follow for the after-boundary
`FindAndDelete` branch. The exact fixture is therefore `consensus-validated`,
not `policy-validated`.

## Limits

The pool signatures use public test keys and the historical out-of-range
`SIGHASH_SINGLE` digest. The puzzle signatures are ordinary deterministic
signatures: there is no grinding, transaction-pinning proof, two-round digest,
or collision-security result. The fixture validates one exact legacy boundary
composition and must not be described as full Binohash. P2WSH and tapscript do
not use these legacy rules.

See the [implementation report](../../research/binohash-codesep/README.md), the
[Binohash overview](binohash.md), and `OP-011`.
