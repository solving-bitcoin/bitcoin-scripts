# Constant-composition Script decoder negative result

- **Question:** Can the 49-digit constant-composition Winternitz encoding be
  decoded back to its 20-byte rank inside Bitcoin Script at a composable cost?
- **Hypothesis:** The existing host decoder does not translate compactly: exact
  lexicographic ranking requires dynamic multinomial buckets, 160-bit rank
  accumulation, and division-like updates that current Script does not provide
  as a native opcode.
- **Comparison objective:** Keep the existing 2,400-byte terminal verifier
  boundary focused on authentication, and avoid silently treating its host
  `decode_message` helper as a Script consumer.
- **Threat model:** All 49 digit values are hostile. A decoder must reject the
  wrong length, out-of-radix values, duplicate/exhausted composition counts,
  and ranks outside the first `2^160` codewords.
- **Execution class:** `unclassified`; inspected design result, with no Script
  decoder claimed.
- **Hard constraints:** preserve the exact composition, recover canonical
  big-endian 20-byte output, and count all tables, rank state, witness items,
  and stack state under the same 1,000-item boundary.

## Result

`ConstantCompositionWinternitz20::decode_message` is already a deterministic
host utility. Porting it directly would require dynamic multinomial bucket
selection and 160-bit arithmetic for every digit position; replacing the
divisions with a static table would expose a large position/count/digit table
whose lifetime and stack cost have not been priced. The authentication
verifier does not need recovered bytes and intentionally leaves this boundary
to a consumer. No compact Script decoder is retained.

This is not a lower bound against a future circuit or a claim that recovery is
impossible. It records the current non-composable boundary and points to
OP-021 for a properly costed decoder experiment.
