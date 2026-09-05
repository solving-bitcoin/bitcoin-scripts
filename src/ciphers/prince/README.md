# PRINCEv2

Bitcoin Script implementation of PRINCEv2 encryption for one 64-bit block with
a generation-time 128-bit key.

## Parameters

- Block size: fixed at 64 bits, represented by 16 nibbles.
- Key size: fixed at 128 bits and embedded in the generated locking fragment;
  no default key exists. Metrics use the all-zero key; fused-row selection
  makes both size and memory key-dependent.
- Encryption only; no public decryption script is currently exposed.

## Script metrics

Boundary: **fragment-with-memory** includes lookup setup, all rounds, output
ordering and cleanup; excludes plaintext pushes and output comparison. Sizes
use the final `compile_with_policy()` serialization with all optimizer passes.
The witness metric serializes only the 16 canonical plaintext ScriptNums,
including item count/lengths; it excludes the tapleaf and control block.

| Fragment | Script size |
| --- | ---: |
| `prince_encrypt(0)` | <!-- metric:prince_encrypt -->6136<!-- /metric:prince_encrypt --> bytes |
| Plaintext witness, all-zero block | <!-- metric:prince_witness_min -->17<!-- /metric:prince_witness_min --> bytes |
| Plaintext witness, no zero nibbles | <!-- metric:prince_witness_max -->33<!-- /metric:prince_witness_max --> bytes |
| Maximum combined main/alt-stack depth | <!-- metric:prince_stack -->633<!-- /metric:prince_stack --> items |
| Fragment non-push operations | <!-- metric:prince_non_push_ops -->3988<!-- /metric:prince_non_push_ops --> |

The zero-key fragment is 6,136 bytes, down from the previous 6,277 bytes
(141 bytes / 2.25%). The published-vector key now costs 6,292 instead of
6,499 bytes (207 bytes / 3.19%). The generator tracks the public nibble order
directly, retires final outputs as it computes them, and includes evacuation
cost in the last quartet schedule. The frequently used final-row selector
occupies the shallowest table slot. Fused rows are selected per key using
setup, lookup-address widths, invocation counts and cleanup in the byte score;
table addresses and cleanup are derived from the selected layout. This is a
bounded heuristic, not a claim of optimal table packing.

The zero-key layout still has 626 memory/state items and a 633-item combined
peak. The published-vector key peaks at 685 items; callers must budget the
actual key's tables. Key XORs remain generation-time constants with no runtime
key region. The 44 M-hat cores each have 82 pre-optimization serialized bytes,
excluding quartet preparation and S-box actions. Quartet planning is cached
independently of the key.

The generator specializes a native Rust translation of BitVM's
[`prince_v2_optimized10.js`](https://github.com/BitVM/bitvm-js/blob/b931a6711ab332fd5923e708c869bed02e39984e/scripts/opcodes/PRINCEv2/prince_v2_optimized10.js),
pinned to commit `b931a6711ab332fd5923e708c869bed02e39984e`. Tests pin the
generated zero-key engine's exact byte length and SHA-256 digest. Script size
is key-dependent because fused constants select different lookup paths.

`prince_encrypt_ref` is a direct Rust translation of the upstream PRINCEv2 C
reference at commit `0c6172dcd85f1fe6a269519093a79c7350fe6e55`.
[`prince_differential.rs`](../../../tests/prince_differential.rs) compiles once
per key and tests real witness inputs in strict tapscript mode. It checks
boundary blocks, seeded random blocks/keys, missing inputs, oversized
ScriptNums and wrong ciphertexts. Its 37 independent C-generated vectors
cover 36 distinct keys with a maximum observed combined stack peak of 725;
[`prince_reference_vectors.c`](../../../tools/prince_reference_vectors.c) and
the fixture JSON record reproduction instructions and the immutable source.

Focused reproduction (no repository-wide metric generation):

```sh
cargo test --locked --release --lib test_prince_script_encrypt
cargo test --locked --release --test prince_differential -- --include-ignored --nocapture
cargo test --locked --release --test primitive_metrics prince_metrics_are_current
```

The randomized integration test defaults to three fixed plus two random keys,
with six boundary plus 32 random blocks per key. Its deterministic ChaCha20
seed is `0x5052494e43455632`; `PRINCE_FUZZ_KEYS`,
`PRINCE_FUZZ_PLAINTEXTS_PER_KEY`, and decimal `PRINCE_FUZZ_SEED` override these.
The independent C fixtures use the same numeric seed with SplitMix64.

## Security

PRINCEv2 has a 128-bit key and 64-bit block. Exhaustive key search is nominally
128-bit, while generic block collisions occur around `2^32` blocks and codebook
coverage at `2^64`. This implementation makes no side-channel claim and should
not be treated as an authenticated-encryption mode.

## Script compatibility and standardness

The fragment uses legacy-compatible stack and arithmetic opcodes, but exceeds
the legacy 201-opcode execution limit. Tapscript is therefore the compatible
script type; bare script, P2SH, and P2WSH are not. The fragment alone does not
satisfy cleanstack because it intentionally returns 16 ciphertext nibbles. A
caller must compare or consume all 16 and leave one truthy item.

Focused tests use `bitcoin-scriptexec` revision
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1` in tapscript context with the combined
1,000-item limit enabled. They reject generated OP_SUCCESSx and conditional
opcodes, so the fragment's static non-push count is also its executed count on
successful inputs. Signature-validation budget consumption is zero. The
integration tests append a separately disclosed, unoptimized 33-byte output
predicate to the exact policy-produced fragment. Evidence is
`differentially-validated`; deployment remains `unclassified` pending complete
transaction/Bitcoin Core and relay-policy validation.

## Witness and hints

No hints are required: zero incremental hint items per invocation and 16 total
plaintext witness/data items. All 16 coexist at script entry. The plaintext is
16 canonical nibbles with nibble 0 (the most significant nibble) on top and
nibble 15 deepest. Range and canonical encoding are caller preconditions;
the fragment does not independently validate all nibble inputs. The key is public in the
locking script. `key` is a `u128` whose upper 64 bits are PRINCEv2 `k0` and
lower 64 bits are `k1`. The generator preserves any unrelated main/alt-stack
prefix, which also counts toward the limit. The zero-key fixture leaves 367
items of headroom; this is not a key-independent composition guarantee.
