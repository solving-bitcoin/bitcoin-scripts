# HASH160

This module composes the repository's byte-oriented SHA-256 and RIPEMD-160
fragments into Bitcoin's `HASH160(x) = RIPEMD160(SHA256(x))` construction.

## Script metrics

The metric covers both hashing fragments and their table setup/cleanup. Message
pushes, digest comparison, and witness serialization are excluded from the
locking-script size. The measured peak is the combined main and alt stack.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| 32-byte input | <!-- metric:hash160_32 -->752651<!-- /metric:hash160_32 --> bytes | <!-- metric:hash160_witness_32 -->65<!-- /metric:hash160_witness_32 --> bytes | <!-- metric:hash160_stack_32 -->856<!-- /metric:hash160_stack_32 --> |
| 32-byte input, shared byte-logic table | <!-- metric:hash160_shared_table_32 -->752327<!-- /metric:hash160_shared_table_32 --> bytes | <!-- metric:hash160_witness_32 -->65<!-- /metric:hash160_witness_32 --> bytes | <!-- metric:hash160_shared_table_stack_32 -->856<!-- /metric:hash160_shared_table_stack_32 --> |

The SHA-256 and RIPEMD-160 stages both use byte-valued stack items. The
intermediate 32-byte SHA-256 digest is consumed directly by RIPEMD-160, so no
host-side serialization or representation conversion is needed. The shared-
table variant keeps the common 256-item byte-logic lookup resident between
stages and saves one setup/cleanup pair.

The representative script exceeds the repository optimizer's 32 KiB input
cutoff and is reported unoptimized. Its measured 856-item peak fits under the
local 1,000-item combined-stack check, but Bitcoin Core consensus and policy
validation have not been performed.

## Stack contract

`hash160(num_bytes)` consumes exactly `num_bytes` byte-valued main-stack items
and leaves the 20 RIPEMD-160 digest bytes with the first digest byte on top.
`hash160_shared_table(num_bytes)` has the same stack contract while reusing one
byte-logic table across both hash stages.
The message length is fixed at generation time and follows the 511-byte limit
of the component hash fragments.

The fragment does not compare the digest or append a clean-stack predicate;
callers must provide the terminal protocol check.
