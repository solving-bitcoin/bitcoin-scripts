# BLAKE3

BLAKE3 hashing implemented with tracked-stack u4/bigint machinery. Generated
compute scripts are run through the pinned `bitcoin-script-stack` peephole
optimizer plus two locally proved stack-identity rewrites to a fixed point.

Two input profiles are public:

- `blake3_short_compute_script` is the script-minimized profile for a
  witness-backed message of `0..=32` bytes. It consumes exactly two numeric u4
  items per byte and synthesizes all padding internally.
- `blake3_compute_script_with_limb` supports `0..=1024` bytes with two
  selected-limb 256-bit groups per block. Limb width is `4..=31`; the
  compatibility wrapper uses 29-bit limbs.

Both profiles implement unkeyed 32-byte hashing only. Keyed mode, derive-key
mode, XOF output, and the multi-chunk tree API are not implemented.

The experimental `ed25519_challenge` module also exposes custom-signature
transcript shapes. These are not stable hash APIs and do not implement RFC
8032 Ed25519:

These experimental generators now use only the repository's centralized
compilation policy. In particular, wrappers larger than 32 KiB receive
`CompileOptions::NONE` and do not run a second fixed-point optimizer pass after
`compile_with_policy()`.

| Experimental transcript | Script bytes | Data items | Hint items | Peak/bound |
| --- | ---: | ---: | ---: | ---: |
| `BLAKE3(R32 || A32 || M32)` | 125,687 | 192 checked u4 | 0 | <=655 |
| `BLAKE3(D32 || A32 || R32 || M32)`, fixed `D32,A32` | 65,208 | 128 checked u4 | 0 | <=591 |
| low 128 bits of fixed-`D32,A32` form | 64,760 | 128 checked u4 | 0 | <=591 |
| low 128 bits, caller-certified u4 input | 63,764 | 128 certified u4 | 0 | <=591 |
| caller-certified input with 337 H16 items preserved | 65,123 | 128 certified u4 + 337 preserved | 0 | 928 combined |
| fixed-`M32` binder + specialized low-128 hash at the H16 frontier | 64,118 | 128 certified u4 + 337 preserved at entry; 64 u4 + 337 after binding | 0 | 864 combined |
| fixed-`M32` hash copied from later-certified packed R | 67,806 | 297 preserved items, including 8 packed R words | 0 | 824 combined |
| fixed-`M32` hash from canonical-u5 R | 67,137 | 391 preserved items, including 51 R digits | 0 | 918 combined |

The second form precomputes the non-root chaining value for the fixed first
block and runs only the final `CHUNK_END|ROOT` compression in Script. A
deterministic host-only test matches the ordinary unkeyed BLAKE3 digest of the
complete 128-byte transcript. Runtime `R` digits must be bound to the same
canonical point encoding used by the curve
equation, and runtime `M32` digits to the intended message source. Both forms
use exactly zero auxiliary witness-hint items.

`key_specialized_compute_script_preserving_truncated_128` omits the four
unused root-output words for a 128-bit challenge schedule. It saves 448 script
bytes and returns 32 rather than 64 u4 items. It is truncation of ordinary
BLAKE3 output, not a different compression function. The generated Script was
not executed, so this row has the same `inspected`/`unclassified` boundary.
The caller-certified variant saves another 996 bytes by relying on a preceding
carrier decoder to prove every transcript item is in `0..16`; using it on raw
witness items would be unsound.

The 337-item preserving instantiation is the exact H16 slope-chain hash
frontier: 288 future packet items, a 41-item current state, and eight packed
`Rtilde` words remain live below the 128 transcript nibbles. The previously
reported 63,766-byte generator was not executable with a prefix:
the packed-XOR backend's `OP_DEPTH` addressing requires its 330 lookup-table
items at the bottom of the main stack. Correctly parking and restoring the 337
preserved items around table construction and cleanup makes the variable-`M32`
hash 65,123 bytes. A strict focused execution reaches 928 combined items.

For the linked constant `M32`, a 128-byte binder instead verifies and consumes
the 64 hostile message nibbles. The specialized compressor folds those eight
fixed words into its addition-table addresses, so its hash frontier is only
337 preserved items plus 64 `R32` nibbles. Binder plus hash is 64,118 bytes
(128 + 63,990) and reaches 864 combined items in a strict focused execution.
The fixture
matches the standard `blake3` crate's low 128 output bits, preserves exact
prefix/`R` order, and rejects malformed, reordered, or extra input. It uses
zero hint items. Applying the policy-only hash delta to the generation-only
H16 component account projects a 3,828,057-byte leaf with
792 entry items (88 hints and 704 trace-data items, all coexisting) and a
strict peak-equivalent schedule of 999. The multi-megabyte leaf itself has not
been executed.

The separate G29 q-free H16 schedule has no transcript carriers. At its hash
boundary, 256 challenge-trace items and the 41-item current state remain. The
67,806-byte helper deep-copies the eight packed R words at word-zero depth 289,
derives their 64 u4 items, hashes the fixed message, and preserves all 297
original items. A focused strict execution peaks at 824, matches host BLAKE3,
preserves the prefix byte-for-byte, and rejects extra input. Packed-word
canonicality is intentionally supplied later by the final derived slope
transition over those untouched originals; omitting that later certification
would be unsound. This boundary has exactly zero hint items. It is composed in
the policy-corrected additive 3,896,335-byte q-free projection, whose 712 entry
data items also contain zero hints and whose analytical arithmetic frontier is
912. The multi-megabyte leaf was not executed.

The G32 hybrid-u5 helper receives 391 preserved items: the 51 canonical
radix-32 `Rtilde` digits, the remaining fifteen challenge packets, and the
92-item current state. Its 2,931-byte converter copies and packs R into 64 u4
items while checking every digit and rejecting the 19-value noncanonical gap;
the fixed-message BLAKE3 body is 64,206 bytes. The 67,137-byte pair contains
45,452 static non-push opcodes, preserves all original items byte-for-byte,
returns 32 digest nibbles, uses exactly zero hint items, and strict-peaks at
918. A focused fixture matches host BLAKE3 and
rejects an out-of-range digit, the first gap encoding, and extra input. The
original 51 R digits remain available for the terminal slope relation.
Together with the four-item first-kernel pool, it gives a 2,999,983-byte
generation-only G32 leaf. That leaf has
803 coexisting entry-data items, zero hints across all 47 transitions, and an
analytical combined-stack maximum of 999. Its multi-megabyte Script
has not been executed, and fixed `M32` is not transaction authorization.

`key_specialized_compute_script_preserving` exposes the same one-compression
construction while preserving a caller-selected main-stack prefix. Preserved
prefixes must use the same table-below-prefix staging described above; older
size projections that counted only a deeper exact-depth constant are invalid.
A separate inspected carrier model stores the 64 runtime transcript bytes in
existing signed-23-bit quotient items, leaving the G29 entry at 764 items; that
composed metric has intentionally not been run.

## Short-input specialization

The short profile keeps only message words that overlap the declared input.
Absent zero words are omitted from every round instead of being materialized on
the stack. In the first round, entirely constant column calls are evaluated by
the Rust generator, while active columns combine literal initial-state words
with the live input and fixed XOR-table rows. Addition queries reuse one
absolute index against an interleaved modulo/carry table. The packed XOR
superstring ends in three copies of row zero, so the same memory also supplies
the modulo-only lookup for discarded most-significant carries. Constant
first-column additions fold literal nibbles into the table address. G-call
order is selected at generation time.

The full XOR matrix is stored as a 171-item shortest common superstring of its
16 fixed-orientation rows rather than as 256 separate items. Two appended
row-zero cycles fuse its 48-entry modulo role, leaving 331 total lookup items.
For inputs with eight live words (29 through 32 bytes), an independent-nibble
register backend also selects physical digit emission order and the
seven-bit-rotation stream origin without runtime normalization. Its shift and
addition tables are introduced only after the 64 message digits are staged,
which shortens every subsequent absolute lookup. The exact-32-byte layout
additionally permutes physical input words and digits to match the consuming
schedule and destructively consumes the final XOR lookup before cleanup.

These are generator transformations: they do not change BLAKE3's seven-round
compression function or remove validation from witness-backed digits.

## Script metrics

The compute metrics are `fragment-with-memory`. They include input range
validation and any representation conversion, 353 bytes of lookup-table setup,
hashing, table cleanup, and digest restoration. Normal cleanup is 166 bytes;
the exact-32 path consumes its final table item and needs 165 bytes. For the
eight-word backend, setup is split into 241 bytes before message staging and
112 bytes afterward. Metrics exclude input pushes or witness serialization and
digest comparison.

| Configuration | Compute script |
| --- | ---: |
| Empty message, 29-bit API | <!-- metric:blake3_empty_limb29 -->64<!-- /metric:blake3_empty_limb29 --> bytes |
| 1 byte, direct checked u4 | <!-- metric:blake3_short_1 -->56124<!-- /metric:blake3_short_1 --> bytes |
| 32 bytes, direct checked u4 | <!-- metric:blake3_short_32 -->59529<!-- /metric:blake3_short_32 --> bytes |
| 32 bytes, selected 4-bit limbs | <!-- metric:blake3_32_limb4 -->61204<!-- /metric:blake3_32_limb4 --> bytes |
| 64 bytes, 4-bit limbs | <!-- metric:blake3_64_limb4 -->64095<!-- /metric:blake3_64_limb4 --> bytes |
| 64 bytes, 29-bit limbs | <!-- metric:blake3_64_limb29 -->72293<!-- /metric:blake3_64_limb29 --> bytes |

Every nontrivial row in this table exceeds the repository optimizer's 32 KiB
input cutoff and receives no additional upstream rewrite passes after the
BLAKE3-specific fixed-point pass.

For the deterministic 32-byte message `00 01 ... 1f`, direct host-side message
pushes are <!-- metric:blake3_push_short_32 -->64<!-- /metric:blake3_push_short_32 -->
bytes. The push, compute fragment, and 128-byte digest comparison compose to
<!-- metric:blake3_complete_short_32 -->59721<!-- /metric:blake3_complete_short_32 -->
bytes. Encoding the same nibbles as canonical witness items takes
<!-- metric:blake3_witness_short_32 -->111<!-- /metric:blake3_witness_short_32 -->
serialized bytes; the valid 64-item maximum is
<!-- metric:blake3_witness_short_32_max -->129<!-- /metric:blake3_witness_short_32_max -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_short_32 -->41134<!-- /metric:blake3_opcodes_short_32 -->
static non-push opcodes, and the executable composition peaks at
<!-- metric:blake3_stack_short_32 -->527<!-- /metric:blake3_stack_short_32 -->
combined main/altstack items.

The corresponding 32-byte selected-limb helper composition peaks at
<!-- metric:blake3_stack_32_limb4 -->527<!-- /metric:blake3_stack_32_limb4 -->
items. Direct u4 therefore saves 1,673 compute bytes on the final shared core and
uses 64 rather than 128 host-push bytes.

For the deterministic 64-byte message `00 01 ... 3f`, host-side 29-bit message
packing is <!-- metric:blake3_push_64_limb29 -->87<!-- /metric:blake3_push_64_limb29 -->
bytes and digest comparison is
<!-- metric:blake3_verify_output -->128<!-- /metric:blake3_verify_output -->
bytes. Their executable composition with the 64-byte compute fragment is
<!-- metric:blake3_complete_64_limb29 -->72508<!-- /metric:blake3_complete_64_limb29 -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_64_limb29 -->47567<!-- /metric:blake3_opcodes_64_limb29 -->
static non-push opcodes; the composition peaks at
<!-- metric:blake3_stack_64_limb29 -->591<!-- /metric:blake3_stack_64_limb29 -->
items.

The helper compositions embed messages and expected digests in the script;
they are deterministic regression fixtures rather than proof-boundary cost
claims. The local strict-stack test executes every direct-input length from 0
through 32 and enforces the 1,000-item limit. This is not a Bitcoin Core
consensus or policy reproduction, so both profiles remain
`research-unlimited`.

## Direct u4 witness layout

`blake3_short_compute_script(n)` requires exactly `2*n` numeric items and
rejects extra main-stack state. Each byte is represented by its high nibble and
then low nibble. Within each four-byte BLAKE3 word, bytes are supplied in reverse
order. For lengths below 32 bytes, words remain in semantic order.

For exactly 32 bytes, let `w0..w7` be the consecutive four-byte words. Their
physical push order is `w1,w4,w3,w7,w6,w2,w0,w5`. Within each word, number the
otherwise canonical nibble items `d0..d7`; their physical order is
`d7,d0,d5,d6,d1,d2,d3,d4`. These are internal stack-routing optimizations.
`blake3_short_message_witness` emits minimally encoded witness items, and
`blake3_push_short_message_script` emits the same layout as script constants;
either helper should be preferred over hand encoding.

Every supplied item is checked as a ScriptNum in `[0, 16)` before it can address
lookup memory. This establishes numeric bounds, not a protocol-level byte
serialization rule; callers that commit to raw encodings must enforce their
own canonicality boundary. The message length is fixed when the script is
generated and must be bound by the surrounding protocol when it is selected
dynamically.

The selected-limb profile range-validates every witness limb that overlaps the
declared message. When the final block has at most 32 message bytes, its second
256-bit group is wholly padding: that profile drops the group without
validation and synthesizes zeros, so callers must not treat ignored values as
bound data. The direct profile has no ignored padding input.

## Security and compatibility

The 256-bit BLAKE3 output has generic 128-bit collision resistance and 256-bit
preimage/second-preimage resistance. Only the single-chunk-tree range supported
by this implementation is in scope.

Generated scripts are far beyond ordinary standard output templates. Treat
them as tapscript research fragments. A complete caller must compare the digest
and leave a clean truthy result; P2SH, P2WSH, and bare deployment are generally
unsuitable.
