# Point validation does not validate an encrypted label translation

The [subset translation experiment](../../research/pointlocks-2026-09-17/subset-translation.md)
connects 460 recovered scalars from an existing Core report to 2,070 binary
rank-input labels. Its 26,484,500-row table takes 794.81 ms median to generate
and 784.15 ms to audit with all secrets disclosed, plus 10.62 ms preparation.
This is not public setup verification. It is one translation instance, with
7,627,536,000 ciphertext bytes; multiple garbled copies are not included.

A deterministic negative test preserves every candidate point but encrypts a
wrong verifier label. A correctly keyed row MAC still passes. Public hashes of
the intended labels detect the bad plaintext only when the row is opened;
they do not certify that unopened rows have the right plaintext. The Bitcoin
publication does not inspect these offchain ciphertexts.

Separately, the public-zero-label shortcut fails with a common free-XOR offset:
one revealed one-label and its public zero-label expose the offset and every
other one-label. A 50-label algebra fixture reproduces that disclosure.

Evidence: **locally-reproduced** for both counterexamples and the table metrics;
**inspected** for their composition implications. Deployment: **unclassified**.
These results exclude the stated shortcuts, not all algebraic translations,
independent-label garblings or noninteractive cut-and-choose protocols.

## Threshold complements improve size, not public binding

The [complement follow-up](../../research/pointlocks-2026-09-17/complement-translation.md)
uses 4-of-50 secret sharing with encrypted off-diagonal shares. It avoids
publishing selected zero-labels and evaluates real garbled rank decoders in a
72.64-ms full generation/opened-audit benchmark. A used ciphertext mutation
still preserves public points and intended label hashes but prevents a future
opening. Auditing a copy with every shared point scalar disclosed also unlocks
other copies using those scalars; it is not a safe public cut-and-choose step.

The later [total message decoder](../../research/pointlocks-2026-09-17/total-message-decoder.md)
adds the missing 2048-bit garbled mixed-radix stage with a total modulo rule.
Its generation and all-secrets audit together take 701.05 ms median for one
complete translation/decoder instance. Resolving that decoding gap does not
validate the encrypted shares or garblings publicly: the ciphertext mutation
and shared-scalar audit objections above still apply.

A concrete attempted algebraic repair replaces PRF pads with public linear
masks over the secp256k1 scalar field. Its eight-candidate example has 56 public
equations, rank 40, and 40 scalar unknowns. Gaussian elimination recovers all
eight point scalars and all 32 polynomial coefficients. This is a
**locally-reproduced**, **unclassified** negative result for that mask family,
not a general impossibility claim. Source and output are linked from the note.

The subsequent [scalar-linear theorem](linear-complement-labels.md) excludes
all direct linear repairs satisfying the stated scalar privacy/complement
conditions when n>=t+2. It does not extend to the current PRF ciphertexts or
nonlinear/group-valued constructions.

The [DDH batch-select follow-up](ddh-batch-select-share-disclosure.md) explores
a group-valued replacement. Its aggregate-only interface delivers the labels,
but adapting it to separately revealed common-shift point scalars exposes both
labels through coefficient differences. That distinct composition failure is
NR-067; it does not follow from the scalar-linear complement theorem.

## WOTS translation does not remove public table binding by itself

A [primary-source follow-up](../../research/pointlocks-2026-09-17/wots-translation-boundary.md)
reproduces the checksum-controlled sharing interface of ePrint2026/1684:
13,056 access-deficit checks and64 reconstructed labels over16 messages.
Changing one ciphertext preserves all WOTS endpoints and the original label
hashes, while a valid opening yields a wrong label. This is another concrete
instance of the standalone wrapper's missing public setup check, not an attack
on the source's honest-garbler privacy or its protocol with cut-and-choose.
No new native point lock, garbled-verifier composition or setup benchmark
follows from those `locally-reproduced`, `unclassified` tests.
