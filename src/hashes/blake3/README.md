# BLAKE3

BLAKE3 hashing for messages up to one 1,024-byte chunk, implemented with the
tracked-stack u4/bigint machinery. Generated compute scripts are run through
the pinned `bitcoin-script-stack` peephole optimizer to a fixed point.

## Parameters

- Message length: `0..=1024` bytes, fixed at generation time.
- Limb width: `4..=31`; default `29` in `blake3_compute_script`.
- Table mode is currently full tables. The documented metric uses a 64-byte
  message and 29-bit limbs.
- Scope: unkeyed 32-byte hashing only. Keyed mode, derive-key mode, XOF output,
  and the multi-chunk tree API are not implemented.

## Script metrics

The compute metric is `fragment-with-memory`: it includes numeric input-limb
range validation, conversion to nibbles, 383 bytes of table setup, hashing, 192 bytes
of table cleanup, and digest restoration. It excludes input pushes and digest
comparison.

| Configuration | Compute script |
| --- | ---: |
| Empty message, 29-bit API | <!-- metric:blake3_empty_limb29 -->64<!-- /metric:blake3_empty_limb29 --> bytes |
| 64 bytes, 4-bit limbs | <!-- metric:blake3_64_limb4 -->68287<!-- /metric:blake3_64_limb4 --> bytes |
| 64 bytes, 29-bit limbs | <!-- metric:blake3_64_limb29 -->76481<!-- /metric:blake3_64_limb29 --> bytes |

For the deterministic message `00 01 ... 3f`, host-side 29-bit message packing
is <!-- metric:blake3_push_64_limb29 -->87<!-- /metric:blake3_push_64_limb29 -->
bytes and digest comparison is
<!-- metric:blake3_verify_output -->128<!-- /metric:blake3_verify_output -->
bytes. Their executable composition with the 64-byte compute fragment is
<!-- metric:blake3_complete_64_limb29 -->76696<!-- /metric:blake3_complete_64_limb29 -->
bytes. This composition embeds the message and expected digest in the script;
it is a helper regression fixture, not a deployable proof boundary.

The 64-byte, 29-bit compute fragment contains
<!-- metric:blake3_opcodes_64_limb29 -->46691<!-- /metric:blake3_opcodes_64_limb29 -->
static non-push opcodes. The executable helper
composition peaks at
<!-- metric:blake3_stack_64_limb29 -->644<!-- /metric:blake3_stack_64_limb29 -->
combined main/altstack items.

Maximum depth is parameter-dependent. Use
`maximum_number_of_altstack_elements_using_blake3` when composing other
altstack users. The local witness-input executor used by differential tests and
the peak metric disables the stack-limit check. Its representative one-block
peak is numerically 644 items, but this is not strict consensus validation; the
construction remains `research-unlimited`.

## Security

The 256-bit BLAKE3 output has generic 128-bit collision resistance and 256-bit
preimage/second-preimage resistance. Only the single-chunk-tree range supported
by this implementation is in scope.

## Script compatibility and standardness

Generated scripts are substantially beyond ordinary standard output templates
and can exceed normal stack/policy limits. Treat them as tapscript research
fragments; P2SH, P2WSH, and bare deployment is generally unsuitable. A complete
caller must verify the digest and leave a clean truthy result.

## Witness and hints

No cryptographic hints are required. Host-known messages and expected digests
are packed directly by `blake3_push_message_script_with_limb` and
`blake3_verify_output_script`; no runtime representation conversion is emitted
for those constants.

The compute fragment range-validates every witness limb that overlaps the
declared message. This establishes numeric bounds, not a byte-unique ScriptNum
encoding; protocols that require encoding canonicality must enforce it at their
boundary. When the final block has at most 32 message bytes, its second 256-bit
group is wholly padding: the fragment drops that group without validation and
synthesizes zeros, so callers must not treat ignored padding values as bound
data.
