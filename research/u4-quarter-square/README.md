# Quarter-square nibble product: initial experiment

Question: can the existing quarter-square identity be specialized to canonical
u4 operands with a 31-item reusable table, improving lifecycle bytes and stack
coexistence versus the current 256-item modulo-16 product table? The private
seed's repeated-block and pair motifs suggested replacing the product grid with
sum/difference symmetry. This is not a new mathematical identity: the existing
secp256k1 field backend already uses it at a different radix.

Hypothesis: `Q(a+b)-Q(abs(a-b))=a*b`, with `Q(x)=floor(x*x/4)`, x=0..30.
The sum and difference have the same parity, so their floor remainders cancel.
An exact table returns a 0..225 ScriptNum product; storing Q modulo16 and adding
16 to a negative difference returns the same modulo16 output as the existing
256-entry table. These output semantics must be measured separately.

Threat model: hostile runtime operands, including encoding aliases, out-of-range
values and missing items. Each canonical nibble check precedes lookup. There
are zero hints, two data items per invocation and 2n for a batch, all present at
entry. Table is script memory. Caller main/alt state and every resident entry
must survive queries. Existing APIs remain unchanged; the prototype preceded the new exact-product API.

Comparison boundary: stage/route runtime pairs from below resident memory,
query in reverse pair order, park products on altstack, drop the table and
restore every output in original order. Both modulo candidates include the
same canonical input boundary, setup, query, cleanup and output restoration;
input pushes and final product comparisons are excluded. Complete leaves compare
all outputs and end in clean OP_TRUE. A separate exact 256-entry table baseline
must use exact products rather than treating modulo output as interchangeable.

Hard constraints: four-byte numeric operations, 520-byte items, combined 1000
items, centralized compilation policy, no disabled multiplication/division
opcodes, no experimental CAT, no hints. Deployment initially unclassified;
strict local tapscript acceptance does not establish Core or policy validity.
Source base: bf9ee0bb34987a9130ad9dc13a06e18fef137296. Existing table multiplication
and field quarter-square sources were inspected; no standalone u4 quarter-square
product entry was found in the catalog/source search. That is a coverage result,
not proof of global novelty.

## Stable implementation and validation boundary

The public `quarter_square::u4_pairwise_mul_exact(n)` now owns its private
31-entry exact table and whole lifecycle. Only this exact 0..225 output variant
is public. The modulo branch remains a research-only Pareto result. Outputs
128..225 use two-byte canonical ScriptNum encodings; consumers must specify
conversion if a transcript expects raw bytes. All intermediates fit four-byte
numeric operations. Both caller stacks survive, with `2*n+34+preserved<=1000`;
n1..483 is explicit, with no default. No hints, authentication or terminal
predicate are supplied by the fragment.

The exact full-table comparison has its own canonical row-index query rather
than using the modulo API outside its documented table contract. At n32 it
costs 1937 fragment / 2034 leaf bytes and 323 combined items, versus 1389/1486/98
for the quarter scan; both serialize 64 ordinary canonical-seven inputs in 129
bytes with zero hints. At n370 it costs 16133/17244/999 versus 15247/16358/774.
At n483 the quarter scan reaches 1000 items with 966 data items, 1935 witness
bytes and 19880/21330 fragment/leaf bytes; that full-table size is unsupported.
The exact frontier tests add runtime main/alt caller items and reject 1001 with
StackSize. Different modulo rows are recorded under
[NR-076](../../knowledge/negative-results/u4-quarter-square-modulo.md).

The named 32-pair metric is `u4_exact_product_metrics_are_current`.
[metrics.json](metrics.json) records every final fragment/leaf hash, witness
serialization/hash, ordinary and hint counts, combined peak, static non-push
count, terminal predicate, compiler/interpreter source and options. All measured
scripts/leaves are below the 32KiB raw threshold and use centralized
CompileOptions::ALL. Cost runs use strict local tapscript, Options::default,
synthetic empty transaction, data-only budget and no signatures. Evidence is
locally-reproduced and deployment unclassified. Dynamic counts and validation
weight are unavailable. No Core/relay transaction claim is made.

The [shared suite](../../tests/u4_product_contract.rs) covers all 256 pairs
individually and as one shared-table batch, asymmetric ordering, six-position
hostile witnesses, canonical versus numeric-only aliases, short input, both
caller stacks, exact resource frontiers and actual compiled range/canonical
mutations caught by the same typed rejection assertion. Range mutants get an
ordinary zero caller item below memory so a bad row index cannot accidentally
fail at OP_PICK and mask the missing validation. Oracle expected-product items
used by the all-pairs test are test-only data and excluded from metric witnesses.
Wrong-product terminal rejection has a valid control and a cleanup mutation.
Artifact checks rebuild every report row and match catalog boundaries and pins.

The measured implementation source is `121dbc16104671914393c2431323f53b474e0e82`.
Catalog parameters pin that immutable measurement tree; this documentation-only
follow-up records its identity.
The delivered PR head identifies the clean integrated tree tested before
submission. Reproduction (host optimization retains assertions and overflow
checks; Script optimization policy is independent):

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example u4_quarter_square_probe > /tmp/u4-quarter-square-reproduced.json
cmp research/u4-quarter-square/metrics.json /tmp/u4-quarter-square-reproduced.json
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test u4_product_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics u4_exact_product_metrics_are_current
python3 tools/kb.py validate
python3 -m unittest discover -s tools -p 'test_*.py'
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

Compiler/interpreter identities are obtained from the producer's embedded
lockfile. The existing quarter-square identity source is registered immutably;
field carry/hint evidence is not inherited and field tests remain excluded.
Remaining complete transaction evidence is [OP-034](../../knowledge/open-problems.md#op-034--complete-quarter-square-product-oracle).
