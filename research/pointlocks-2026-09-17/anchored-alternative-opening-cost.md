# Alternative nonces: an upper-work strategy to analyze

Question: does the anchored five-check candidate justify an80-bit extraction
claim merely because all five short signatures have distinct contexts? **No
such lower bound has been established.** A concrete strategy mixes a moderate
search for nonce points with transaction grinding. It must be included in any
future security analysis.

This note describes an attack strategy and a heuristic cost model, not a
successful native attack, lower bound, or proof of optimality. No astronomical
search has been executed. Source: [cost model](anchored_alternative_opening_cost.py);
[numerical output](anchored_alternative_opening_cost.json). Evidence: **inspected**;
deployment: **unclassified**.

## Strategy for one target label

An adversarial creator retains t for T=tG. For each candidate transaction the
public anchor digest z0 determines p=(t-z0)/rT. The creator therefore knows the
private key for the dynamically recovered P even though the public extractor
does not. The creator can use ordinary ECDSA signing with other known-to-him
nonces; there is no requirement that those nonces be publicly known.

1. Find five different nonce scalars k_j whose r_j=x(k_jG) has positive DER
   length23. Retain the scalars privately and use a separate nonce for each
   context. Exclude G/2 and any publicly known simple nonce relations.
2. Vary a transaction or ancestor field, recompute actual native anchor/short
   digests and p, and sign each context using its assigned nonce. The standard
   six flags supply up to six choices per context.
3. Stop when the low-S value in every selected signature has DER length30.
   Each signature then has exactly7+23+30=60 bytes. The same retained t makes
   the anchor valid. All other publication labels can use ordinary G/2 openings.

No nonce repeats within the attacked key, so the original known-G/2 and
repeated-nonce branches fail on that label. The
[implemented affine-relation fallback](nonce-relation-extraction.md) now also
tests signed GLV relations and permits explicit public translations. The
strategy must avoid nondegenerate tested relations as well. This does not
prove that every possible extractor fails: a successful replacement extractor
would itself be progress. The intended model already requires unrelated nonce
scalars, rather than adjacent integers or a reused endomorphism orbit; its
numerical estimates are unchanged by this implementation extension.

## Disclosed cost model

For a positive DER integer of length b, its interval is

    2^(8*(b-1)-1) <= value < 2^(8*b-1),   b > 1.

Model nonce x-coordinates as uniform in the secp256k1 base field. A23-byte r
then has probability approximately(1-1/256)*2^-73 per tested nonce point.
Finding five such points costs approximately **2^75.33 nonce-point trials**.
This is an expectation in that model, not a measured bound or an assumption
that every curve-coordinate distribution is exactly uniform.

Given a fresh pseudorandom digest, low-S normalization puts s into the30-byte
interval with probability approximately(1-1/256)*2^-16. With six independent
flag opportunities per context, requiring success in all five contexts gives
approximately **2^67.10 transaction trials**, or **2^72.01 scalar-signature
checks** if all30 alternatives are evaluated at every trial. SHA256 work to
construct the actual digests is additional and depends on the transaction
template and reusable midstates. A nonce-point trial and a scalar check are
different operations; these exponents are not interchangeable security bits.

The rare-event calculation assumes suitably independent fresh digests after
the chosen transaction/ancestor variation, conditional on the anchor. This
needs a template-level analysis; simply changing an output leaves some NONE
digests unchanged. Varying an ancestor changes the current input's outpoint,
which BIP143 includes even with ANYONECANPAY. An actual strategy must pay for
whatever ancestor construction and eventual publication are required. The
current user model explicitly permits alternative transaction choices unless
the construction binds them. This note does not assume that policy's six flags
exhaust the consensus choices.

Larger precomputed nonce pools can supply several candidates per context.
The script scans a bounded set of such parameters, keeping point-search and
signature-check costs separate. Bucket the nonces by context to prevent an
accidental repeated nonce from making the target extractable. Neither this
scan nor the simpler five-point calculation justifies choosing a repetition
count as a proven security parameter. Full adaptive, multi-target analysis,
other nonce relations and a public extraction theorem remain open.

## Full-byte consensus follow-up

The [Core follow-up](anchored-rounds-limits.md) confirms all256 flag bytes on
the unchanged cap60/five-context script, with only six policy-accepted. The
cost-model scan now includes256 choices and rounds3..16. At d=5, one screened
strategy uses32 nonce candidates per context with24-byte r and29-byte s. Its
estimated costs are2^72.33 nonce-point trials,2^55.03 transaction trials and
2^70.35 scalar-signature checks, plus hashing. A six-flag security analysis
would omit this accepted freedom. These are heuristic counts in distinct
units, not an executed attack or a proved lower bound.

Varying the checked input's sequence changes a field included in every BIP143
preimage, including NONE and ANYONECANPAY. That gives31 bits of variation with
the relative-locktime-disable bit retained. Larger searches additionally need
other fields or ancestor variation. Their setup/transaction work must be
counted; the template's available nonce space cannot be assumed unbounded.
