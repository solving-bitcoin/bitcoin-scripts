# Sparse exact-threshold tapscript signatures

Can a witness with only the selected signatures and their key depths
beat a dense exact-threshold `CHECKSIGADD` witness? The hypothesis is
that removing empty placeholders reduces complete witness size when the
required count is small relative to the key list. Compare both encodings
for the same distinct x-only keys, exact number of signers, selected keys,
transaction fields and default sighash. Every signature and routing depth
is hostile. The hard constraints are valid fixed x-only keys, canonical
depths, the 1,000-item combined limit, correct full-witness signature
budget accounting and the central compilation policy.

The public generator pushes the fixed key list once, with the last key
at depth zero. Each witness pair contains a signature and its depth.
The shallowest selected depth is consumed first. Initialize the previous
depth to −1. Check canonical encoding, strict increase and the upper
bound before using each depth. The saved depth and current signature sit
above the key table, so `OP_PICK` uses `depth+2`. It can address only the
fixed 32-byte keys for a well-shaped suffix. `OP_CHECKSIGVERIFY` consumes
that signature and key copy. Strict order prevents counting a key twice,
and duplicate keys are rejected at generation. Clear the retained depth
and table after all checks. The fragment uses no altstack.

The comparator follows the exact-threshold dense script in
[BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
and [BIP 387](https://github.com/bitcoin/bips/blob/master/bip-0387.mediawiki).
It runs one native signature opcode for each public key with an empty
witness placeholder for every unselected key. The repository and PR search
found indexed stack selection and transaction-aware signature examples,
with different contracts. The sparse verifier combines fixed-key routing
with checks on the native Taproot transaction signature message.

## Matched signed leaves

| Threshold | Schedule | Script bytes | Data witness bytes | Complete witness bytes | Ordinary items | Hint items | Hint bytes | Peak | Executed non-push ops | Initial budget | Charged |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 of 16 | Indexed | 635 | 268 | 940 | 4 | 4 | 7 | 28 | 77 | 990 | 200 |
| 4 of 16 | Dense | 546 | 273 | 856 | 16 | 0 | 0 | 17 | 17 | 906 | 200 |
| 2 of 64 | Indexed | 2,197 | 134 | 2,368 | 2 | 2 | 3 | 72 | 67 | 2,418 | 100 |
| 2 of 64 | Dense | 2,178 | 193 | 2,408 | 64 | 0 | 0 | 65 | 65 | 2,458 | 100 |

Use depths `[0,4,8,15]` and `[0,63]`, respectively. Keys are generated from
the integers 1 through `n` encoded as 32-byte secret scalars for the test.
The Rust fixture builds and signs each exact Taproot leaf separately, with
one supplied prevout, one input, one output and no annex. Each checked
leaf ends with one true item and uses whole-artifact optimizer `ALL`.
Data-witness bytes include count and length prefixes for ordinary items
and hints. Dense empty placeholders are ordinary data. Complete witness
bytes also include the tapscript and 33-byte control block. Non-witness
transaction serialization is excluded. Hint bytes include each hint's
length prefix. All items coexist at entry. These successful leaves
execute every non-push opcode. The initial budget is 50 plus complete
witness bytes, with 50 charged for every nonempty signature check.

At 2 of 64, reducing the data witness by 59 bytes offsets 19 extra script
bytes for a 40-byte complete witness saving. The 4-of-16 case uses 84 more
complete bytes. Both indexed cases have a larger peak. See the
[negative result](../negative-results/sparse-tapscript-threshold.md).

## Evidence and composition

Evidence is `locally-reproduced`; execution is `unclassified`. The tests
check the Taproot output commitment using the supplied prevout, then
execute the signed transaction context with `Exec::new_tapscript` and
complete-witness accounting. Stack limits and MINIMALIF are enabled.
Numeric minimality and experimental OP_CAT are disabled. The script
enforces depth canonicality independently. These transactions use a
deterministic synthetic outpoint and were not funded on Core.

The fragment consumes exactly `2k` witness items, comprising `k`
ordinary signatures and `k` routing hints. The combined peak is at most
`n + 2k + 4` plus preserved caller state, including future preloaded
inputs. The constructor rejects widths and thresholds outside the
resulting no-caller bound. At 1 of 994, depth 993, the exact fixture
has one ordinary item, one hint, a peak of 1,000, and rejects one more
entry item. Its 33,827-byte complete leaf is **unoptimized** `NONE`
because raw size exceeds 32 KiB. The complete witness is 33,933 bytes,
the data witness is 69 bytes, and 1,012 non-push operations execute.
The signature charge is 50. No caller data is present.

The caller establishes the exact suffix and key policy, including
which transaction sighashes the application permits. Tests cover
out-of-range and noncanonical depths, repeated-signature reuse,
descending selection, wrong-key and wrong-leaf signatures, empty
signatures, changed transactions, short and surplus witnesses, and
duplicate public keys.

```sh
cargo test --locked --test sparse_threshold_contract
cargo test --locked --test primitive_metrics sparse_threshold_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The locked compiler and interpreter revisions are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
See the [implementation README](../../src/signatures/sparse_threshold/README.md)
and catalog `signature/sparse-tapscript-threshold`.
