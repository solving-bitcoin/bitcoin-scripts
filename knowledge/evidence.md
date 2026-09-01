# Evidence, confidence, and freshness

## Evidence ladder

1. **Reported:** copied from a primary source with exact provenance.
2. **Inspected:** source or construction reviewed locally, but not reproduced.
3. **Locally reproduced:** deterministic local code reproduces the claim.
4. **Differentially validated:** reproduced and checked against an independent
   implementation or authoritative interpreter.

Evidence applies per claim. A record uses the strongest level shared by its
core correctness and metric claims; exceptions belong in `limitations`.

## Deployment classes

- **Consensus validated:** accepted with the applicable consensus checks.
- **Policy validated:** also accepted by the documented node policy.
- **Consensus incompatible:** a known rule prevents the configuration.
- **Research unlimited:** execution deliberately disables a consensus limit.
- **Unclassified:** insufficient evidence.

Opcode availability, consensus validity, standard relay policy, economic
practicality, and cryptographic security are separate claims.

## Freshness

Every record has `as_of`. Reviews should check upstream commits, Bitcoin Core
semantics, catalog alternatives, local reproduction, and open-problem status.
The catalog does not silently expire results, but `python3 tools/kb.py stale`
lists entries older than the requested number of days.

## Absence and inference

- “Not in this catalog” means unknown coverage.
- “No implementation” means none linked here, not that none exists.
- “Current best” is allowed only on a comparison page with a stated filtered
  dataset and objective.
- Inferences must say what observations they derive from.
