# Integer commitments

This module contains two constructions that authenticate a small integer and
return it to the surrounding Bitcoin Script. They are commitment primitives,
not general-purpose hash functions.

- **Hash path:** a nonce/preimage is hashed through one of two branches for
  each committed bit. The verifier authenticates the path and reconstructs a
  1–31-bit non-negative Script integer.
- **Preimage length:** a SHA-256 preimage is authenticated and its byte length,
  minus a public offset, becomes the committed integer.

Both are experimental. In particular, a hash-path commitment without a secret,
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

## Script metrics

Sizes are the generated locking fragments. Witness sizes use Bitcoin's
serialized witness encoding, including item counts and length prefixes.
Maximum stack items count the combined main and alt stacks and are measured by
the tests with the listed witness.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `verify_hash_path_to_integer(31, commitment)` | <!-- metric:hash_path_integer_31 -->520<!-- /metric:hash_path_integer_31 --> bytes | <!-- metric:hash_path_integer_witness_31 -->78<!-- /metric:hash_path_integer_witness_31 --> bytes (32-byte nonce, 31 bits) | <!-- metric:hash_path_integer_stack_31 -->34<!-- /metric:hash_path_integer_stack_31 --> |
| `verify_preimage_length(commitment)` | <!-- metric:preimage_length_default -->44<!-- /metric:preimage_length_default --> bytes | <!-- metric:preimage_length_witness_min -->18<!-- /metric:preimage_length_witness_min -->–<!-- metric:preimage_length_witness_max -->524<!-- /metric:preimage_length_witness_max --> bytes (16–520-byte preimage) | <!-- metric:preimage_length_stack -->3<!-- /metric:preimage_length_stack --> |

## Security

The hash path ends in a 160-bit digest, capping generic collision resistance at
80 bits and generic preimage or second-preimage resistance at 160 bits. Binding
also depends on the security of the mixed SHA-256/RIPEMD-160 path. Hiding is
only computational and depends on the entropy and secrecy of the initial
preimage; a public or guessable preimage permits enumeration of small values.

The preimage-length construction uses SHA-256, giving generic 128-bit collision
resistance and 256-bit preimage/second-preimage resistance. Its hiding property
depends on unpredictable preimage bytes; length alone is not secret once the
opening is revealed.

## Script compatibility and standardness

All used opcodes exist in bare script, P2SH, P2WSH, and tapscript. The
preimage-length fragment is small enough for those forms when composed into an
otherwise valid script. Bare outputs remain non-standard under default relay
policy.

Hash-path compatibility is parameter-dependent. Its repeated branches and
hashes can exceed the 201-opcode legacy limit, making wider configurations
(including the measured 31-bit integer-returning variant) tapscript-only.
Tapscript still enforces the 1,000-item combined stack limit, the 520-byte
per-item limit, witness weight, and execution budget. The implementation
explicitly enforces canonical `[]`/`[1]` bits, including in legacy script.

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
- `verify_preimage_length`: `... preimage -> ... length_minus_offset`.

The hash-path construction generalizes the former `BitHash128` code. The old
`hashes::bithash` names remain deprecated compatibility wrappers using 128 bits
and an empty initial preimage. The preimage-length idea and hash-path family are
independently implemented from the descriptions in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/).
