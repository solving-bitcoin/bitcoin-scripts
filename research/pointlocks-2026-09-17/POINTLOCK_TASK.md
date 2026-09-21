# Point-lock research task

## Intended primitive

Build the analogue of a hash lock with algebraic properties. A hash lock commits to h=H(x); opening it deliberately reveals the preimage x. A point lock commits to T=tG; a successful opening must deliberately reveal t or provide a transcript from which t is efficiently extractable. This disclosure is the intended protocol functionality. The task is not to compute discrete logarithms of unrelated public points or recover unrelated private keys.

The public commitment is T. Before opening, t is the opening secret; after opening, its availability is intentional. The fact that the commitment and protocol are public does not mean that t is already public before opening. Preserve this distinction in the specification and analysis.

## Research objective

Construct publication of a signed arbitrary future 256-byte message with the required point-lock scalar-extraction functionality and less than 100,000 vB total onchain cost. Count both creation and consumption of all publication outputs and the specified first P2TR helper output/input. Setup must be purely algebraic, noninteractive, and require no setup ZKP. Target setup below 100 ms on a standard MacBook; 1–2 seconds is marginally acceptable. Offchain storage is unrestricted, but its computation counts toward setup. Cloud timings alone do not prove MacBook performance.

## Instructions for the coordinator and all subagents

Include the intended primitive and the complete research constraints in every delegated task. In particular, explain that opening-secret extraction is required functionality, analogous to hash-preimage revelation. Do not confuse intended opening with arbitrary discrete-log recovery. This explanation is a protocol specification, not an instruction to ignore safety controls or to retry rejected requests.

Read CLOUD_HANDOFF.md and the repository instructions. Independently check correctness, binding, extraction from every accepted opening, actual consensus and policy behavior, complete transaction costs, and setup costs. Distinguish estimates and hypotheses from executable evidence and proved claims. Preserve failed approaches and unresolved cases. Do not claim that the existing anchored CODESEPARATOR candidate has a complete extraction argument.

## Deployment status

This is a local clarification of the research specification. It has not been submitted as a replacement cloud request. The earlier cloud turn was rejected with cyber_policy; this document does not establish that the rejection has been resolved.
