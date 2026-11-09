# Binohash-style subset indices with exact HORS authentication

This local toy composes the exact-index HORS opening with 2-of-3 `OP_ROLL`
selection. It copies the two index items from one opening before HORS consumes
them, then uses those same copies to select pool tags. There is no second
witness selector. A final relation checks that the selected tag sum corresponds
to the ordered index pair.

## Evidence and scope

The three ordered pairs `[0,1]`, `[0,2]`, and `[1,2]` pass strict local
tapscript execution. Wrong preimages, out-of-range, duplicate, reversed,
negative, and nonminimal indices fail; nonminimal controls also fail with the
executor's `MINIMALDATA` option disabled. An extra data item fails clean-stack.
This is `locally-reproduced` evidence with `unclassified` execution. It is not
a Bitcoin Core spend and does not exercise legacy `FindAndDelete`, ECDSA, or
the Binohash two-round protocol.

The [implementation README](../../research/binohash-hors-subset/README.md)
records the input order, same-witness comparison, and exact measured boundary.
For `n=3,t=2`, the final policy-produced composition is 153 bytes and uses a
38-byte serialized four-item data witness, **zero hint items**, a 12-item
combined stack peak, and 68 static non-push opcodes. The same opening with
clamped HORS alone is 89 bytes, 9 stack items, and 19 static non-push opcodes;
exact HORS alone is 110 bytes, 10 items, and 35 static non-push opcodes. These
are distinct script boundaries, and the static counts are not executed-opcode
measurements.

## Security and remaining work

The pool tags are numeric test markers, not ECDSA signatures. The fixed test
preimages are public. Authentication here means that the script checks each
supplied opening against a committed hash and routes exactly those checked
indices into selection. It does not establish secret-key or one-time security,
transaction digest binding, consensus validity, relay acceptance, or a
cryptographic Binohash claim. A funded legacy spend with real signatures and
private one-time-key lifecycle remains open under [OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles)
and [OP-011](../open-problems.md#op-011--reproduce-binohash).
