# A hash commitment does not enforce a Schnorr key type

A public HASH160 identifier can commit to a one-byte value.
The test constructs an otherwise matching leaf without a
key-length guard. Under local tapscript execution, a one-byte
key and nonempty dummy signature succeed with a charge of 50.
No Schnorr signature is checked on that unknown key type.

The [guarded leaf](../../src/signatures/hash_keyset/README.md)
rejects the same committed short key before charging a signature
check. A 32-byte invalid x-only point also fails the native check.
See [BIP342](https://bips.dev/342/#rules-for-signature-opcodes).

At one key, embedding the key directly gives the same 35-byte
leaf and saves 33 complete witness bytes relative to the HASH160
scan. The [measured comparison](../comparisons/hash160-schnorr-keyset.md)
records how the result changes as the set grows.

Evidence is `locally-reproduced`. Execution is `unclassified`.
