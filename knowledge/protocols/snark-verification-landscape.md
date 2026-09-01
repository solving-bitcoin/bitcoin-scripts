# SNARK verification strategy landscape

The local BN254 implementation represents one strategy: generate large Bitcoin
Script arithmetic fragments, then split them into challengeable protocol
chunks. The active BitVM ecosystem also contains a garbled-SNARK-verifier
repository that moves the verifier into deterministic streaming garbled
circuits.

These approaches are adjacent, not directly comparable primitive rows:

| Strategy | Bitcoin Script role | Main knowledge needed |
| --- | --- | --- |
| Arithmetic/chunked verifier | Executes disputed arithmetic chunks | Script, hints, stack, authenticated state |
| Garbled verifier | Verifies garbled computation/protocol artifacts | Circuit gates, labels, streaming memory, on-chain authentication |

Before claiming a frontier result, pin both upstream revisions and normalize
on-chain bytes, off-chain work, assumptions, rounds, failure/challenge behavior,
and verifier memory. Source `bitvm-garbled-snark-verifier` is discovery evidence
only until reproduced locally.
