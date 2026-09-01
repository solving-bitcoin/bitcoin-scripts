# Integer commitments

This module contains three constructions that authenticate a small integer and
return it to the surrounding Bitcoin Script. They are commitment primitives,
not general-purpose hash functions.

- **Hash path:** a nonce/preimage is hashed through one of two branches for
  each committed bit. The verifier authenticates the path and reconstructs a
  1–31-bit non-negative Script integer.
- **Four-way hash path:** two bits select one of four fixed-length hash
  codewords per base-4 digit, reducing witness items and peak stack usage.
- **Preimage length:** a SHA-256 preimage is authenticated and its byte length,
  minus a public offset, becomes the committed integer.

All three are experimental. In particular, a hash-path commitment without a secret,
high-entropy preimage is deterministic and does not hide a small integer.

## Parameters

### Hash path

- `bit_width`: required, with no default. Integer reconstruction accepts
  `1..=31`; the generic bit-path verifier can be wider subject to the enclosing
  script's limits.
- `preimage`: caller-chosen byte string. Use a secret, high-entropy nonce when
  hiding is required; it must fit the 520-byte stack-element limit.
- `commitment`: 20 bytes. A false bit applies SHA-256, a true bit applies
  RIPEMD-160, and a final RIPEMD-160 produces the commitment.
- Variants consume the path, retain its bits on the altstack, or reconstruct a
  Script integer. There is no default variant.

### Preimage length

- `commitment`: SHA-256 of the preimage, fixed at 32 bytes.
- `offset`: `0..=520`. `verify_preimage_length` defaults to 16;
  `verify_preimage_length_with_offset` requires an explicit value.
- The revealed integer is `preimage.len() - offset`, so the preimage length
  must be in `offset..=520`.

### Four-way hash path

- `bit_width`: required, with no default. Integer reconstruction accepts
  `1..=31` and uses `ceil(bit_width / 2)` base-4 digits. For an odd width the
  most-significant digit is restricted to `0..=1`.
- `preimage`: caller-chosen byte string with the same secrecy and 520-byte
  element-limit obligations as the binary hash path.
- `commitment`: 20 bytes. Each digit selects a two-stage codeword over
  SHA-256 (`S`) and RIPEMD-160 (`R`): `0 -> SS`, `1 -> SR`, `2 -> RS`, and
  `3 -> RR`. A final RIPEMD-160 produces the commitment.
- The generic verifier consumes digits or retains them on the altstack; the
  integer verifier hashes and reconstructs them most-significant first in one
  pass. There is no default variant.

## Script metrics

Sizes are the generated locking fragments. Witness sizes use Bitcoin's
serialized witness encoding, including item counts and length prefixes.
Maximum stack items count the combined main and alt stacks and are measured by
the tests with the listed witness.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `verify_hash_path_to_integer(31, commitment)` | <!-- metric:hash_path_integer_31 -->520<!-- /metric:hash_path_integer_31 --> bytes | <!-- metric:hash_path_integer_witness_31 -->78<!-- /metric:hash_path_integer_witness_31 --> bytes (32-byte nonce, 31 bits) | <!-- metric:hash_path_integer_stack_31 -->34<!-- /metric:hash_path_integer_stack_31 --> |
| `verify_four_way_hash_path_to_integer(31, commitment)` | <!-- metric:four_way_hash_path_integer_31 -->453<!-- /metric:four_way_hash_path_integer_31 --> bytes | <!-- metric:four_way_hash_path_integer_witness_31 -->61<!-- /metric:four_way_hash_path_integer_witness_31 --> bytes (32-byte nonce, 16 digits) | <!-- metric:four_way_hash_path_integer_stack_31 -->19<!-- /metric:four_way_hash_path_integer_stack_31 --> |
| `verify_preimage_length(commitment)` | <!-- metric:preimage_length_default -->44<!-- /metric:preimage_length_default --> bytes | <!-- metric:preimage_length_witness_min -->18<!-- /metric:preimage_length_witness_min -->–<!-- metric:preimage_length_witness_max -->524<!-- /metric:preimage_length_witness_max --> bytes (16–520-byte preimage) | <!-- metric:preimage_length_stack -->3<!-- /metric:preimage_length_stack --> |

## Security

The hash path ends in a 160-bit digest, capping generic collision resistance at
80 bits and generic preimage or second-preimage resistance at 160 bits. Binding
also depends on the security of the mixed SHA-256/RIPEMD-160 path. Hiding is
only computational and depends on the entropy and secrecy of the initial
preimage; a public or guessable preimage permits enumeration of small values.

The four-way path has the same 160-bit final-digest bounds and additionally
assumes that mixed SHA-256/RIPEMD-160 schedules remain binding across the four
codewords. Every codeword contains exactly two primitive hashes. This is
essential: the superficially cheaper mapping to `SHA256`, `HASH256`,
`RIPEMD160`, and `HASH160` has deterministic aliases because the latter two
double-hash opcodes are compositions of the former primitives. The fixed-length
code avoids those structural aliases but is still a non-standard construction
without a dedicated cryptanalysis.

The preimage-length construction uses SHA-256, giving generic 128-bit collision
resistance and 256-bit preimage/second-preimage resistance. Its hiding property
depends on unpredictable preimage bytes; length alone is not secret once the
opening is revealed.

## Script compatibility and standardness

All used opcodes exist in bare script, P2SH, P2WSH, and tapscript. The
preimage-length fragment is small enough for those forms when composed into an
otherwise valid script. Bare outputs remain non-standard under default relay
policy.

Hash-path compatibility is parameter-dependent. Repeated branches and hashes
can exceed the 201-opcode legacy limit. The binary path explicitly enforces
canonical `[]`/`[1]` bits, including in legacy script. The four-way path is
more restrictive: its compact range proof relies on tapscript's
consensus-enforced `MINIMALIF`. It is unsafe under legacy or P2WSH consensus
semantics without adding explicit range checks, even though every emitted
opcode exists there. Both measured 31-bit variants are tapscript-only.
Tapscript still enforces the 1,000-item combined stack limit, the 520-byte
per-item limit, witness weight, and execution budget.

Neither fragment is a complete locking script by itself: callers must compose
it with a predicate that leaves one truthy cleanstack item. See
[`docs/script-types.md`](../../docs/script-types.md) and
[`docs/standardness.md`](../../docs/standardness.md).

## Witness and hints

Neither construction uses arithmetic hints.

For the integer hash path, witness serialization order is `bitN-1, ...,
bit0, preimage`; the preimage is therefore on top at script entry. A false bit
is the empty vector and a true bit is `[01]`. `hash_path_integer_witness`
produces this canonical encoding.

For the four-way integer path, witness order is `least_significant_digit, ...,
most_significant_digit, preimage`; the most-significant digit is processed
first. Zero is encoded as the empty vector and `1..=3` as `[01]`, `[02]`, or
`[03]`. Tapscript `MINIMALIF` rejects negative and out-of-range values. The
helper produces minimal encodings, and the local executor's `MINIMALDATA`
setting rejects non-minimal test witnesses. Numeric minimality is not itself a
tapscript consensus rule, so callers must treat the digit value, rather than a
unique byte representation, as committed.

For the preimage-length construction, the witness contains the committed
preimage as one item. The preimage is consumed and only the resulting integer
remains.

## Stack contract and operational notes

- `verify_hash_path_to_integer`: `... bitN-1 ... bit0 preimage -> ... value`.
  It temporarily stores all bits on the altstack and empties them before
  returning.
- `verify_hash_path`: `... bitN-1 ... bit0 preimage -> ... true`.
- `verify_hash_path_to_altstack` leaves true on the main stack and the bits on
  the altstack, with bit `N-1` on top.
- `verify_four_way_hash_path_to_integer`: `... least_significant_digit ...
  most_significant_digit preimage -> ... value`. It keeps only a running
  accumulator on the altstack and empties it before returning.
- `verify_four_way_hash_path`: `... digitN-1 ... digit0 preimage -> ... true`.
- `verify_four_way_hash_path_to_altstack` leaves digit `N-1` on top of the
  altstack.
- `verify_preimage_length`: `... preimage -> ... length_minus_offset`.

The hash-path construction generalizes the former fixed-width `BitHash128`
prototype. It is exposed only through the parameterized `commitments::hash_path`
API. The preimage-length idea and hash-path family are independently implemented
from the descriptions in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/).

At 31 bits the four-way variant uses 67 fewer locking-script bytes, 17 fewer
serialized-witness bytes, and 15 fewer peak stack items than the binary path.
The savings come from processing two bits per dispatcher, reconstructing the
integer during the hash pass, specializing the one-bit leading digit, and
using tapscript `MINIMALIF` as the terminal selector-range check. Correctness,
malformed-witness, and metric tests run in the repository's tapscript-context
executor, and a representative test separately enables its stack-limit check.
Because the general witness-input helper used by metrics disables that limit,
the recorded execution class remains `research-unlimited`, not Bitcoin Core
consensus or relay-policy validation.
