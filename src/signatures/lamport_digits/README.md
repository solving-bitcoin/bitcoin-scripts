# Multi-digit Lamport commitments

`lamport_digits::lamport_digits_commit(images)` opens `d` digits of radix `2^w`.
Each digit has `2^w` public HASH160 images; the witness gives, per digit, the
claimed value and the preimage of that value's image, and the script leaves the
`d` values on the stack in order. A value outside `0..2^w` and any wrong or
swapped preimage abort the script; unlike `lamport::lamport_2bit_commit`, nothing
is clamped. It uses no hints. `lamport_digit_images` derives public images from
deterministic 16-byte secrets (`SHA-256(seed || digit || value)` truncated), the
secret length used in the Winternitz comparison tables.

Strictly one-time: a revealed preimage is public, and the commitment authenticates
only the value left on the stack, not a transaction. HASH160 bounds apply
(80-bit collision resistance). No signature, covenant or Core validation claim.

## Script metrics

Fragment-only boundary: range check, image pushes, selection, hash check, image
cleanup and value restoration for every digit; input pushes, terminal predicate
and transaction framing excluded. Witness bytes serialize the count and every item
for the fixture digit `v_d = (37*d + 5) mod radix`, with one-byte digit values and
17-byte serialized preimages; a zero digit value is an empty item, so the
maximum is at most one byte per digit larger. Peak uses a terminal drop of the
digits under strict local execution.

32-bit message, two bits per digit (16 digits, 4 images each):

| Script bytes | Witness bytes | Witness items | Hint items | Combined peak | Static non-push opcodes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| <!-- metric:lamport_digits_32_w2 -->1615<!-- /metric:lamport_digits_32_w2 --> | <!-- metric:lamport_digits_32_w2_witness -->301<!-- /metric:lamport_digits_32_w2_witness --> | <!-- metric:lamport_digits_32_w2_witness_items -->32<!-- /metric:lamport_digits_32_w2_witness_items --> | 0 | <!-- metric:lamport_digits_32_w2_stack -->37<!-- /metric:lamport_digits_32_w2_stack --> | <!-- metric:lamport_digits_32_w2_opcodes -->239<!-- /metric:lamport_digits_32_w2_opcodes --> |

160-bit message, two bits per digit (80 digits): <!-- metric:lamport_digits_160_w2 -->8079<!-- /metric:lamport_digits_160_w2 --> script bytes
and <!-- metric:lamport_digits_160_w2_witness -->1501<!-- /metric:lamport_digits_160_w2_witness --> witness bytes, <!-- metric:lamport_digits_160_w2_total -->9580<!-- /metric:lamport_digits_160_w2_total --> in total.

See the [knowledge page](../../../knowledge/primitives/lamport-digits.md) for the
digit-width design space and the comparison with Winternitz.
