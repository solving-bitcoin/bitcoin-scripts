# Public scalar AND checks do not preserve one-message label access

The [public-gate experiment](../../research/pointlocks-2026-09-17/public-algebraic-gate.md)
tests replacing encrypted garbling data with scalar relations that anyone
can verify through point commitments. Its AND gate passes a public algebraic
correctness check, but an opening for 01 or 10 also yields the complete bound
input-label pair for 00. Public affine offsets can make all six commitments
distinct without preventing this recovery.

This rules out that gate as the complete message-authentication interface
under the active goal. It does not refute output authenticity: the recovered
alternative has the same clear output. The related privacy-free formula
garbling explicitly permits some such label leakage, and its verification
interface receives private encoding information. Its guarantees therefore
cannot be silently strengthened to ours.

Four focused tests cover 64 honest evaluations, 32 alternative-input
recoveries and malformed-setup/opening controls. Evidence:
**locally-reproduced**; deployment: **unclassified**. No Bitcoin execution,
new transaction size or full setup benchmark is claimed. Other garblings or
additional secret authentication inputs are outside this example.
